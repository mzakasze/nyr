# dock_nyr/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse, HttpResponseBadRequest
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.core.serializers import serialize
from django.utils import timezone
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
import json
import logging
from .forms import StockForm, RegisterForm
from .models import Stock, DeletedStock, RotomHistory, RotomState, RotomSummary
from django.utils.html import escape
import datetime
from django.utils import timezone
from django.core.cache import cache
from django.db import IntegrityError
from django.db.models.functions import Coalesce, Cast
from django.db.models import Value, Sum, Count, Q, F, IntegerField
from django.db.models.fields.json import KeyTextTransform
import re

logger = logging.getLogger(__name__)

# Lista ID naczep ROTOM
ROTOM_IDS = [
    'SK240UM', 'NWE90SP', 'WGM94990', 'ST5666H', 'WGM9312P',
    'WGM9469P', 'WGM93246', 'SK888NC', 'WGM8421P', 'SK018XA', 'RDE40RG',
    'SLU02W2', 'WGM9532P', 'ST6698H', 'RDE70RM', 'EBE21575', 'DX30059',
    'WGM8300R', 'OKLWW96', 'WGM9045R', 'WZ4925R', 'WGM7653P',
    'WGM9309P', 'WGM93138', 'SPI98FC'
]
ROTOM_IDS_UPPER = [rid.upper() for rid in ROTOM_IDS]


# === Widoki uwierzytelniania (bez zmian) ===
def login_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
                logger.info(f"User {username} logged in successfully.")
                return redirect(next_url)
            else:
                logger.warning(f"Failed login attempt for username: {username} (user not found or wrong password).")
                messages.error(request, 'Invalid login or password.')
        else:
            logger.warning(f"Invalid login form submitted. Errors: {form.errors.as_json()}")
            messages.error(request, 'Invalid login or password.')
    else:
        form = AuthenticationForm()
    context = {'form': form, 'app_version': settings.APP_VERSION}
    return render(request, 'registration/login.html', context)

def register_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            logger.info(f"New user registered: {username}")
            messages.success(request, f'Account created for {username}! You can now login.')
            return redirect('login')
        else:
             error_message = "Please correct the errors below: "
             for field, errors in form.errors.items():
                 error_message += f"{field}: {', '.join(errors)} "
             logger.warning(f"User registration failed. Errors: {form.errors.as_json()}")
             messages.error(request, error_message)
    else:
        form = RegisterForm()
    context = {'form': form, 'app_version': settings.APP_VERSION}
    return render(request, 'registration/register.html', context)

def logout_view(request):
    if request.user.is_authenticated:
        logger.info(f"User {request.user.username} logged out.")
        logout(request)
        messages.info(request, "You have been logged out.")
    return redirect(settings.LOGOUT_REDIRECT_URL)


# === Główne widoki aplikacji ===
@login_required
def stock_list(request):
    return render_stock_page(request, 'dock_nyr_stock.html', show_deleted=False)

@login_required
def nyr_summary(request):
    return render_stock_page(request, 'nyr_summary.html', show_deleted=True)

def render_stock_page(request, template_name, show_deleted=False):
    """Renderuje stronę listy stocków lub podsumowania."""
    try:
        rotom_stats = {}
        if template_name == 'nyr_summary.html':
            rotom_data = calculate_rotom_status_changes()
            rotom_stats = rotom_data

        table_rows = []
        if show_deleted:
            deleted_stocks_qs = DeletedStock.objects.all()
            # Przekazujemy queryset do funkcji liczącej
            total = calculate_totals_from_deleted(deleted_stocks_qs)
            table_rows = [
                create_stock_row(request, stock, index + 1, is_deleted=True)
                for index, stock in enumerate(deleted_stocks_qs.order_by('-deleted_at'))
            ]
        else:
            stocks_qs = Stock.objects.all()
            # Przekazujemy queryset do funkcji liczącej
            total = calculate_totals(stocks_qs)
            table_rows = [
                create_stock_row(request, stock, index + 1, is_deleted=False)
                for index, stock in enumerate(stocks_qs.order_by('start_time'))
            ]

        context = {
            'table_rows': table_rows,
            'total': total,
            'user': request.user,
            'app_version': settings.APP_VERSION,
            'range_102_123': range(102, 124),
            'range_01_28': range(1, 29)
        }

        context.update(rotom_stats)

        return render(request, template_name, context)

    except Exception as e:
        logger.error(f"Critical error rendering stock page '{template_name}': {str(e)}", exc_info=True)
        messages.error(request, "Wystąpił krytyczny błąd podczas ładowania strony. Proszę spróbować ponownie później lub skontaktować się z administratorem.")
        error_template = 'dock_nyr_base.html'
        return render(request, error_template, {'error_message': 'Nie można załadować danych.'}, status=500)


@require_POST
@login_required
def clear_summary_stocks(request):
    """Usuwa wszystkie rekordy z DeletedStock ORAZ resetuje liczniki ROTOM w bazie danych."""
    try:
        if not request.user.is_superuser:
             logger.warning(f"User {request.user.username} attempted to clear summary without permission.")
             return JsonResponse({'success': False, 'error': 'Brak uprawnień'}, status=403)

        deleted_count, _ = DeletedStock.objects.all().delete()
        logger.info(f"User {request.user.username} cleared {deleted_count} summary stocks.")

        RotomState.objects.all().delete()
        summary_data, _ = RotomSummary.objects.get_or_create(pk=1)
        summary_data.reset()
        logger.info(f"User {request.user.username} also reset the persistent ROTOM state and counters in the database.")

        return JsonResponse({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'Usunięto {deleted_count} pozycji z podsumowania oraz zresetowano liczniki ROTOM.'
        })
    except Exception as e:
        logger.error(f"Error clearing summary stocks and ROTOM data by user {request.user.username}: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Wystąpił wewnętrzny błąd podczas czyszczenia archiwum i liczników.'
        }, status=500)


# === Funkcje pomocnicze ===

def calculate_rotom_status_changes():
    """
    <<< ZMIANA: Wprowadzono logikę inicjalizacji, aby zapobiec zliczaniu wszystkich
    aktywnych naczep po resecie. >>>
    """
    logger.info("--- [ROTOM] Starting calculation (using database persistence) ---")

    # Krok 1: Pobierz obiekt podsumowania z bazy
    summary_data, _ = RotomSummary.objects.get_or_create(pk=1)

    # Krok 2: Pobierz aktualny stan naczep z tabeli Stock
    rotom_regex = r"\b(" + "|".join(re.escape(rid) for rid in ROTOM_IDS_UPPER) + r")\b"
    possible_rotoms = Stock.objects.filter(line__iregex=rotom_regex).order_by('-last_edited_at')
    current_stock_map = {}
    assigned_stock_pks = set()
    for stock in possible_rotoms:
        if stock.pk in assigned_stock_pks:
            continue
        stock_line_upper = stock.line.upper()
        for trailer_id in ROTOM_IDS_UPPER:
            if re.search(r"\b{}\b".format(re.escape(trailer_id)), stock_line_upper):
                if trailer_id not in current_stock_map:
                    current_stock_map[trailer_id] = stock.ISA
                    assigned_stock_pks.add(stock.pk)
                    break

    # Krok 3: Sprawdź, czy system wymaga inicjalizacji (pierwsze uruchomienie po resecie)
    if not summary_data.is_initialized:
        logger.info("[ROTOM] System is not initialized. Establishing baseline state without counting changes.")
        RotomState.objects.all().delete()  # Wyczyść stary stan na wszelki wypadek
        for trailer_id in ROTOM_IDS_UPPER:
            current_isa = current_stock_map.get(trailer_id)
            status = 'active' if current_isa is not None else 'released'
            RotomState.objects.create(
                trailer_id=trailer_id,
                last_known_isa=current_isa,
                status=status
            )
        summary_data.is_initialized = True
        summary_data.save()
        logger.info("[ROTOM] Baseline established. System is now initialized.")
        # Zwróć aktualne (wyzerowane) liczniki bez dalszego przetwarzania
        return {
            'reloaded_rotoms': len(summary_data.reloaded_trailers),
            'released_rotoms': len(summary_data.released_trailers),
            'reloaded_trailer_list': summary_data.reloaded_trailers,
            'released_trailer_list': summary_data.released_trailers
        }

    # Krok 4: Jeśli system jest zainicjalizowany, wykonaj standardową logikę porównawczą
    logger.info(f"[ROTOM] System initialized. Comparing current state with stored state.")
    previous_states_qs = RotomState.objects.all()
    previous_state = {state.trailer_id: {'isa': state.last_known_isa, 'status': state.status} for state in previous_states_qs}

    state_changed = False
    for trailer_id in ROTOM_IDS_UPPER:
        prev_info = previous_state.get(trailer_id, {'isa': None, 'status': 'released'})
        current_isa = current_stock_map.get(trailer_id)

        if str(prev_info.get('isa')) != str(current_isa):
            state_changed = True
            logger.info(f"[ROTOM] Change detected for [{trailer_id}]: ISA changed from '{prev_info.get('isa')}' to '{current_isa}'")

            if current_isa is not None and prev_info.get('status') == 'released':
                logger.info("-> LOGIC: Marking as RELOADED (from empty/released)")
                if trailer_id in summary_data.released_trailers:
                    summary_data.released_trailers.remove(trailer_id)
                if trailer_id not in summary_data.reloaded_trailers:
                    summary_data.reloaded_trailers.append(trailer_id)

            elif current_isa is not None and prev_info.get('status') == 'active':
                logger.info("-> LOGIC: Marking as RELOADED (ISA value changed)")
                if trailer_id not in summary_data.reloaded_trailers:
                     summary_data.reloaded_trailers.append(trailer_id)

            elif current_isa is None and prev_info.get('status') == 'active':
                logger.info("-> LOGIC: Marking as RELEASED")
                if trailer_id in summary_data.reloaded_trailers:
                    summary_data.reloaded_trailers.remove(trailer_id)
                if trailer_id not in summary_data.released_trailers:
                    summary_data.released_trailers.append(trailer_id)

            new_status = 'active' if current_isa is not None else 'released'
            RotomState.objects.update_or_create(
                trailer_id=trailer_id,
                defaults={'last_known_isa': current_isa, 'status': new_status}
            )

    if state_changed:
        logger.info(f"[ROTOM] State changed. Saving new summary to database: R:{summary_data.reloaded_trailers}, F:{summary_data.released_trailers}")
        summary_data.save()
    else:
        logger.info("[ROTOM] No state changes detected.")

    return {
        'reloaded_rotoms': len(summary_data.reloaded_trailers),
        'released_rotoms': len(summary_data.released_trailers),
        'reloaded_trailer_list': summary_data.reloaded_trailers,
        'released_trailer_list': summary_data.released_trailers
    }


def create_stock_row(request, stock_obj, row_number, is_deleted=False):
    """Generuje HTML dla pojedynczego wiersza tabeli stocków (aktywnych lub usuniętych)."""
    try:
        if is_deleted:
            data = stock_obj.original_stock_data
            original_user = data.get('user', 'N/A')
            created_at_iso = data.get('created_at')
            formatted_creation_time = "N/A"
            if created_at_iso:
                try:
                    dt_obj = datetime.datetime.fromisoformat(created_at_iso.replace('Z', '+00:00'))
                    formatted_creation_time = timezone.localtime(dt_obj).strftime('%Y-%m-%d %H:%M')
                except (ValueError, TypeError):
                    logger.warning(f"Could not parse deleted stock created_at '{created_at_iso}' for DeletedStock ID {stock_obj.id}")
                    formatted_creation_time = created_at_iso
            else:
                start_time_str_fallback = data.get('start_time', '')
                if start_time_str_fallback:
                    try:
                        dt_obj_fallback = datetime.datetime.fromisoformat(start_time_str_fallback.replace('Z', '+00:00'))
                        formatted_creation_time = f"{timezone.localtime(dt_obj_fallback).strftime('%Y-%m-%d %H:%M')} (SBD/SLA)"
                    except (ValueError, TypeError):
                         logger.warning(f"Could not parse fallback start_time '{start_time_str_fallback}' for DeletedStock ID {stock_obj.id}")
                         formatted_creation_time = f"{start_time_str_fallback} (SBD/SLA)"


            start_time_str = data.get('start_time', '')
            formatted_start_time = "N/A"
            if start_time_str:
                 try:
                     dt_obj = datetime.datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                     formatted_start_time = timezone.localtime(dt_obj).strftime('%Y-%m-%d %H:%M')
                 except (ValueError, TypeError):
                     formatted_start_time = start_time_str


            sbd_color_status = data.get('sbd_sla_color_status', 'none')
            sbd_cell_style = ""
            if sbd_color_status == 'red':
                sbd_cell_style = 'style="background-color: #d60606; color: white; border: 2px solid black;"'
            elif sbd_color_status == 'yellow':
                sbd_cell_style = 'style="background-color: #bdb02b; color: white; border: 2px solid black;"'

            deleted_time_str = "N/A"
            if stock_obj.deleted_at:
                deleted_time_str = timezone.localtime(stock_obj.deleted_at).strftime('%Y-%m-%d %H:%M')

            deleted_by = stock_obj.deleted_by or 'N/A'
            delay_text = data.get('delay', '') or ""
            delay_attr = f'data-full-delay="{escape(delay_text)}"' if len(delay_text) > 100 else ""

            added_by_cell_content = f"{escape(original_user)} ({escape(formatted_creation_time)})"
            added_by_title = f"Stock originally added by: {escape(original_user)} at {escape(formatted_creation_time)}. Deleted by: {escape(deleted_by)} at {escape(deleted_time_str)}"
            deleted_on_text = f"{escape(deleted_time_str)} by <i>{escape(deleted_by)}</i>"

            row_html = f"""
                <tr data-stock-id="{stock_obj.id}" class="deleted-stock-row">
                    <td>{row_number}</td>
                    <td>{escape(data.get('ISA', ''))}</td>
                    <td {sbd_cell_style}>{escape(formatted_start_time)}</td>
                    <td>{escape(data.get('line', ''))}</td>
                    <td>{escape(data.get('NVFPP', ''))}</td>
                    <td>{escape(data.get('NVF', ''))}</td>
                    <td>{escape(data.get('NVF_MIX', ''))}</td>
                    <td>{escape(data.get('MIX', ''))}</td>
                    <td>{escape(data.get('SB', ''))}</td>
                    <td>{escape(data.get('FBA', ''))}</td>
                    <td>{escape(data.get('TSI_PAX', ''))}</td>
                    <td>{escape(data.get('TSI', ''))}</td>
                    <td>{escape(data.get('TSI_MIX_P', ''))}</td>
                    <td>{escape(data.get('TSI_MIX_U', ''))}</td>
                    <td>{escape(data.get('comment', ''))}</td>
                    <td {delay_attr}>{escape(delay_text[:100])}{'...' if len(delay_text) > 100 else ''}</td>
                    <td title="{added_by_title}">{added_by_cell_content}</td>
                    <td>{deleted_on_text}</td>
                </tr>
            """
            return row_html.replace(">None<", "><").replace(">null<", "><")
        else:
            stock = stock_obj
            last_edited_info = ""
            if stock.last_edited_by and stock.last_edited_at:
                try:
                    local_last_edited_at = timezone.localtime(stock.last_edited_at)
                    last_edited_info = f"Last edited by: {escape(stock.last_edited_by)} at {local_last_edited_at.strftime('%Y-%m-%d %H:%M')}"
                except Exception as e:
                    logger.error(f"Error formatting last_edited_at for active stock {stock.id}: {e}")
                    last_edited_info = "Error formatting edit time"

            formatted_start_time = "N/A"
            if stock.start_time:
                try:
                    start_time_aware = stock.start_time if timezone.is_aware(stock.start_time) else timezone.make_aware(stock.start_time, timezone.get_default_timezone())
                    local_start_time = timezone.localtime(start_time_aware)
                    formatted_start_time = local_start_time.strftime('%Y-%m-%d %H:%M')
                except Exception as e:
                    logger.error(f"Error formatting start_time for active stock {stock.id}: {e}")
                    formatted_start_time = "Error"


            formatted_created_at = "N/A"
            if stock.created_at:
                try:
                    local_created_at = timezone.localtime(stock.created_at)
                    formatted_created_at = local_created_at.strftime('%Y-%m-%d %H:%M')
                except Exception as e:
                    logger.error(f"Error formatting created_at for active stock {stock.id}: {e}")
                    formatted_created_at = "Error"


            edit_url = reverse('edit_stock', args=[stock.pk])
            delete_url = reverse('delete_stock', args=[stock.pk])

            can_edit = request.user.has_perm('dock_nyr.change_stock')
            can_delete = request.user.has_perm('dock_nyr.delete_stock')

            actions_html = ""
            if can_edit:
                actions_html += f'<a href="{edit_url}" class="btn-edit">EDIT</a> '
            if can_delete:
                actions_html += f'<a href="{delete_url}" class="btn-delete">DELETE</a>'
            if not actions_html:
                actions_html = "No actions"

            delay_text = stock.delay or ""
            delay_attr = f'data-full-delay="{escape(delay_text)}"' if len(delay_text) > 100 else ""

            added_by_cell_content = f"{escape(stock.user)}"
            added_by_title = f"Added by: {escape(stock.user)} at {escape(formatted_created_at)}. {escape(last_edited_info)}"

            row_html = f"""
                <tr data-stock-id="{stock.id}" class="active-stock-row">
                    <td>{row_number}</td>
                    <td><a href="https://fc-inbound-dock-hub-eu.aka.amazon.com/en_US/#/dockmaster/appointment/ktw5/view/{stock.ISA}/appointmentDetail" target="_blank" rel="noopener noreferrer">{stock.ISA}</a></td>
                    <td>{escape(formatted_start_time)}</td>
                    <td>{escape(stock.line)}</td>
                    <td>{escape(stock.NVFPP)}</td>
                    <td>{escape(stock.NVF)}</td>
                    <td>{escape(stock.NVF_MIX)}</td>
                    <td>{escape(stock.MIX)}</td>
                    <td>{escape(stock.SB)}</td>
                    <td>{escape(stock.FBA)}</td>
                    <td>{escape(stock.TSI_PAX)}</td>
                    <td>{escape(stock.TSI)}</td>
                    <td>{escape(stock.TSI_MIX_P)}</td>
                    <td>{escape(stock.TSI_MIX_U)}</td>
                    <td>{escape(stock.comment)}</td>
                    <td {delay_attr}>{escape(delay_text[:100])}{'...' if len(delay_text) > 100 else ''}</td>
                    <td title="{added_by_title}">{added_by_cell_content}</td>
                    <td>{actions_html}</td>
                </tr>
            """
            return row_html.replace(">None<", "><").replace(">null<", "><")

    except Exception as e:
        logger.error(f"Error creating stock row (is_deleted={is_deleted}, obj_id={stock_obj.id if stock_obj else 'N/A'}): {str(e)}", exc_info=True)
        colspan = 18
        return f'<tr><td colspan="{colspan}">Error loading data for this row. Please contact administrator.</td></tr>'


# ----------------------------------------------------------------------------------
# ZOPTYMALIZOWANE FUNKCJE - WNĘTRZE ZMIENIONE, DZIAŁANIE ZEWNĘTRZNE IDENTYCZNE
# ----------------------------------------------------------------------------------

def calculate_totals(stocks_queryset):
    """
    Zoptymalizowana i POPRAWIONA wersja funkcji obliczającej sumy.
    Wykorzystuje podejście hybrydowe: większość obliczeń w bazie danych,
    skomplikowane wyjątki (UNVERIFIED) w Pythonie dla 100% zgodności.
    """
    # Definicje warunków do filtrowania w bazie danych
    is_oc_q = Q(comment__icontains='#oc#')
    is_rotom_q = Q(comment__icontains='#rotom#')
    is_ats_q = Q(comment__icontains='#ats#')
    is_carrier_q = Q(comment__icontains='#carrier#')
    is_unsell_q = Q(comment__icontains='#unsell#')
    is_wro1_sell_q = Q(comment__icontains='#wro1_sell#')
    is_mix_q = Q(comment__icontains='#mix#')
    is_pax_q = Q(comment__icontains='#pax#')
    is_ll_pax_q = Q(comment__icontains='#ll pax#')
    is_karma_q = Q(comment__icontains='#karma#')
    is_tl_q = Q(comment__icontains='#tl#')
    is_hv_q = Q(comment__icontains='#hv#')
    is_cage_q = Q(comment__icontains='#cage#')
    is_prep_q = Q(comment__icontains='#prep#')
    is_oversize_q = Q(comment__icontains='#oversize#')
    is_dock_q = Q(line__icontains='dock')
    
    # << POPRAWKA: Filtr #d2d# stosowany jest indywidualnie do sum, nie do całości >>
    no_d2d_q = ~Q(comment__icontains='#d2d#')
    
    def sum_or_zero(field, filter_q=Q()):
        return Coalesce(Sum(field, filter=filter_q), 0)

    current_pallets_sum = Coalesce(F('NVFPP'), 0) + Coalesce(F('NVF_MIX'), 0) + Coalesce(F('TSI_PAX'), 0) + Coalesce(F('TSI_MIX_P'), 0) + Coalesce(F('SB'), 0)
    current_quantity_sum = Coalesce(F('NVF'), 0) + Coalesce(F('MIX'), 0) + Coalesce(F('TSI'), 0) + Coalesce(F('TSI_MIX_U'), 0) + Coalesce(F('FBA'), 0)
    
    # Krok 1: Wykonaj większość obliczeń w bazie danych
    totals = stocks_queryset.aggregate(
        # << POPRAWKA: Te liczniki IGNORUJĄ filtr #d2d#, tak jak w oryginale >>
        OC_count=Count('id', filter=is_oc_q),
        ROTOM_count=Count('id', filter=is_rotom_q & Q(ISA__isnull=False) & ~Q(ISA=0)),
        ATS_count=Count('id', filter=is_ats_q),
        CARRIER_count=Count('id', filter=is_carrier_q),

        # << POPRAWKA: Wszystkie poniższe sumy MUSZĄ uwzględniać filtr #d2d# >>
        SB_pallets_total=sum_or_zero('SB', filter_q=no_d2d_q),
        NVF_PP_pallets=sum_or_zero('NVFPP', filter_q=~is_oc_q & no_d2d_q),
        NVF_PP_quantity=sum_or_zero('NVF', filter_q=~is_oc_q & no_d2d_q),
        NVF_MIX_pallets=sum_or_zero('NVF_MIX', filter_q=~is_oc_q & no_d2d_q),
        NVF_MIX_quantity=sum_or_zero('MIX', filter_q=~is_oc_q & no_d2d_q),
        NVF_OC_quantity=sum_or_zero('NVF', filter_q=is_oc_q & no_d2d_q) + sum_or_zero('MIX', filter_q=is_oc_q & no_d2d_q),
        NVF_SB_quantity=sum_or_zero('FBA', filter_q=no_d2d_q),
        TSI_PAX_pallets=sum_or_zero('TSI_PAX', filter_q=no_d2d_q),
        TSI_PAX_quantity=sum_or_zero('TSI', filter_q=no_d2d_q),
        TSI_MIX_SELLABLE_pallets=sum_or_zero('TSI_MIX_P', filter_q=~is_unsell_q & ~is_wro1_sell_q & no_d2d_q),
        TSI_MIX_SELLABLE_quantity=sum_or_zero('TSI_MIX_U', filter_q=~is_unsell_q & ~is_wro1_sell_q & no_d2d_q),
        TSI_WRO1_SELL_pallets=sum_or_zero('TSI_MIX_P', filter_q=is_wro1_sell_q & no_d2d_q),
        TSI_WRO1_SELL_quantity=sum_or_zero('TSI_MIX_U', filter_q=is_wro1_sell_q & no_d2d_q),
        TSI_MIX_UNSELL_pallets=sum_or_zero('TSI_MIX_P', filter_q=is_unsell_q & no_d2d_q),
        TSI_MIX_UNSELL_quantity=sum_or_zero('TSI_MIX_U', filter_q=is_unsell_q & no_d2d_q),
        PAX_NVF_PP_pallets=sum_or_zero('NVFPP', filter_q=is_pax_q & ~is_oc_q & ~is_karma_q & no_d2d_q),
        PAX_NVF_PP_quantity=sum_or_zero('NVF', filter_q=is_pax_q & ~is_oc_q & ~is_karma_q & no_d2d_q),
        PAX_TSI_PAX_pallets=sum_or_zero('TSI_PAX', filter_q=is_pax_q & ~is_karma_q & no_d2d_q),
        PAX_TSI_PAX_quantity=sum_or_zero('TSI', filter_q=is_pax_q & ~is_karma_q & no_d2d_q),
        PAX_FBA_pallets=sum_or_zero('SB', filter_q=is_ll_pax_q & no_d2d_q),
        PAX_FBA_quantity=sum_or_zero('FBA', filter_q=is_ll_pax_q & no_d2d_q),
        PAX_OC_pallets=sum_or_zero('NVFPP', filter_q=is_ll_pax_q & is_oc_q & no_d2d_q) + sum_or_zero('NVF_MIX', filter_q=is_ll_pax_q & is_oc_q & no_d2d_q),
        PAX_OC_quantity=sum_or_zero('NVF', filter_q=is_ll_pax_q & is_oc_q & no_d2d_q) + sum_or_zero('MIX', filter_q=is_ll_pax_q & is_oc_q & no_d2d_q),
        PAX_CC_pallets=sum_or_zero('NVFPP', filter_q=is_ll_pax_q & is_carrier_q & no_d2d_q) + sum_or_zero('NVF_MIX', filter_q=is_ll_pax_q & is_carrier_q & no_d2d_q),
        PAX_CC_quantity=sum_or_zero('NVF', filter_q=is_ll_pax_q & is_carrier_q & no_d2d_q) + sum_or_zero('MIX', filter_q=is_ll_pax_q & is_carrier_q & no_d2d_q),
        PAX_KARMA_pallets=sum_or_zero('NVFPP', filter_q=is_karma_q & no_d2d_q) + sum_or_zero('TSI_PAX', filter_q=is_karma_q & no_d2d_q),
        PAX_KARMA_quantity=sum_or_zero('NVF', filter_q=is_karma_q & no_d2d_q) + sum_or_zero('TSI', filter_q=is_karma_q & no_d2d_q),
        MIX_BACKLOG_NVF_pallets=sum_or_zero('NVF_MIX', filter_q=is_mix_q & ~is_oc_q & no_d2d_q),
        MIX_BACKLOG_NVF_quantity=sum_or_zero('MIX', filter_q=is_mix_q & ~is_oc_q & no_d2d_q),
        MIX_BACKLOG_TSI_pallets=sum_or_zero('TSI_MIX_P', filter_q=is_mix_q & ~is_unsell_q & ~is_wro1_sell_q & no_d2d_q),
        MIX_BACKLOG_TSI_quantity=sum_or_zero('TSI_MIX_U', filter_q=is_mix_q & ~is_unsell_q & ~is_wro1_sell_q & no_d2d_q),
        MIX_FBA_pallets=sum_or_zero('SB', filter_q=is_mix_q & no_d2d_q),
        MIX_FBA_quantity=sum_or_zero('FBA', filter_q=is_mix_q & no_d2d_q),
        MIX_OC_pallets=sum_or_zero('NVFPP', filter_q=is_mix_q & is_oc_q & no_d2d_q) + sum_or_zero('NVF_MIX', filter_q=is_mix_q & is_oc_q & no_d2d_q),
        MIX_OC_quantity=sum_or_zero('NVF', filter_q=is_mix_q & is_oc_q & no_d2d_q) + sum_or_zero('MIX', filter_q=is_mix_q & is_oc_q & no_d2d_q),
        MIX_WRO1_SELL_pallets=sum_or_zero('TSI_MIX_P', filter_q=is_wro1_sell_q & no_d2d_q),
        MIX_WRO1_SELL_quantity=sum_or_zero('TSI_MIX_U', filter_q=is_wro1_sell_q & no_d2d_q),
        MIX_UNSELL_pallets=sum_or_zero('TSI_MIX_P', filter_q=is_unsell_q & no_d2d_q),
        MIX_UNSELL_quantity=sum_or_zero('TSI_MIX_U', filter_q=is_unsell_q & no_d2d_q),
        SPECIAL_TL_pallets=Sum(current_pallets_sum, filter=is_tl_q & no_d2d_q),
        SPECIAL_TL_quantity=Sum(current_quantity_sum, filter=is_tl_q & no_d2d_q),
        SPECIAL_HV_pallets=Sum(current_pallets_sum, filter=is_hv_q & no_d2d_q),
        SPECIAL_HV_quantity=Sum(current_quantity_sum, filter=is_hv_q & no_d2d_q),
        SPECIAL_CAGE_pallets=Sum(current_pallets_sum, filter=is_cage_q & no_d2d_q),
        SPECIAL_CAGE_quantity=Sum(current_quantity_sum, filter=is_cage_q & no_d2d_q),
        SPECIAL_PREP_pallets=Sum(current_pallets_sum, filter=is_prep_q & no_d2d_q),
        SPECIAL_PREP_quantity=Sum(current_quantity_sum, filter=is_prep_q & no_d2d_q),
        SPECIAL_OVERSIZE_pallets=Sum(current_pallets_sum, filter=is_oversize_q & no_d2d_q),
        SPECIAL_OVERSIZE_quantity=Sum(current_quantity_sum, filter=is_oversize_q & no_d2d_q),
        DOCK_TOTAL_PALLETS=Sum(current_pallets_sum, filter=is_dock_q & no_d2d_q),
        CC_units=sum_or_zero('NVF', filter_q=is_carrier_q & no_d2d_q) + sum_or_zero('MIX', filter_q=is_carrier_q & no_d2d_q) + sum_or_zero('TSI', filter_q=is_carrier_q & no_d2d_q) + sum_or_zero('TSI_MIX_U', filter_q=is_carrier_q & no_d2d_q),
        TOTAL_BACKLOG_DISPLAY=sum_or_zero('NVF', filter_q=no_d2d_q) + sum_or_zero('MIX', filter_q=no_d2d_q) + sum_or_zero('FBA', filter_q=no_d2d_q) + sum_or_zero('TSI', filter_q=no_d2d_q) + sum_or_zero('TSI_MIX_U', filter_q=no_d2d_q),
    )

    # Krok 2: Uzupełnij pola, które wymagają logiki nieprzenoszalnej do bazy (UNVERIFIED)
    totals["UNVERIFIED_SB_pallets"] = 0
    totals["UNVERIFIED_SB_quantity"] = 0
    totals["UNVERIFIED_CC_pallets"] = 0
    totals["UNVERIFIED_CC_quantity"] = 0
    
    for stock in stocks_queryset:
        comment = (stock.comment or "").lower()
        if "#d2d#" in comment:
            continue
            
        tags_found = re.findall(r'#([^#]+)#', comment)
        comment_tags = {tag.strip() for tag in tags_found}

        is_unverified_sb_combo = comment_tags in [
            {'do sprawdzenia'},
            {'do sprawdzenia', 'deutp'},
            {'do sprawdzenia', 'slamd'}
        ]
        is_unverified_cc_combo = (comment_tags == {'carrier', 'do sprawdzenia'})

        if is_unverified_sb_combo or is_unverified_cc_combo:
            totals["UNVERIFIED_SB_pallets"] += stock.SB or 0
            totals["UNVERIFIED_SB_quantity"] += stock.FBA or 0
            totals["UNVERIFIED_CC_pallets"] += (stock.NVFPP or 0) + (stock.NVF_MIX or 0)
            totals["UNVERIFIED_CC_quantity"] += (stock.NVF or 0) + (stock.MIX or 0)

    # Krok 3: Obliczenia końcowe, które muszą być wykonane w Pythonie
    totals["NVF_OC_pallets"] = totals.get("OC_count", 0)
    totals["NVF_SB_pallets"] = totals.get("SB_pallets_total", 0)
    totals["NVF_TOTAL_DISPLAY"] = (totals.get("NVF_PP_quantity", 0) + totals.get("NVF_MIX_quantity", 0) + totals.get("NVF_OC_quantity", 0) + totals.get("NVF_SB_quantity", 0))
    totals["TSI_TOTAL_DISPLAY"] = (totals.get("TSI_PAX_quantity", 0) + totals.get("TSI_MIX_SELLABLE_quantity", 0) + totals.get("TSI_WRO1_SELL_quantity", 0) + totals.get("TSI_MIX_UNSELL_quantity", 0))
    totals["PAX_TOTAL_DISPLAY"] = (totals.get("PAX_NVF_PP_quantity", 0) + totals.get("PAX_TSI_PAX_quantity", 0) + totals.get("PAX_FBA_quantity", 0) + totals.get("PAX_OC_quantity", 0) + totals.get("PAX_CC_quantity", 0) + totals.get("PAX_KARMA_quantity", 0))
    totals["MIX_TOTAL_DISPLAY"] = (totals.get("MIX_BACKLOG_NVF_quantity", 0) + totals.get("MIX_BACKLOG_TSI_quantity", 0) + totals.get("MIX_WRO1_SELL_quantity", 0) + totals.get("MIX_UNSELL_quantity", 0) + totals.get("MIX_FBA_quantity", 0) + totals.get("MIX_OC_quantity", 0))
    totals["UNVERIFIED_TOTAL_DISPLAY"] = totals["UNVERIFIED_SB_quantity"] + totals["UNVERIFIED_CC_quantity"]
    max_dock_pallets = 800
    dock_total = totals.get("DOCK_TOTAL_PALLETS") or 0
    totals["DOCK_FULLNESS_PERCENTAGE"] = (dock_total / max_dock_pallets) * 100 if max_dock_pallets > 0 else 0
    totals["DOCK_FULLNESS_PERCENTAGE"] = min(totals["DOCK_FULLNESS_PERCENTAGE"], 100)
    totals["NVF_pallets"] = totals.get("NVF_PP_pallets", 0) + totals.get("NVF_MIX_pallets", 0)
    totals["NVF_units"] = totals.get("NVF_PP_quantity", 0) + totals.get("NVF_MIX_quantity", 0)
    totals["TSI_pallets"] = (totals.get("TSI_PAX_pallets", 0) + totals.get("TSI_MIX_SELLABLE_pallets", 0) + totals.get("TSI_WRO1_SELL_pallets", 0) + totals.get("TSI_MIX_UNSELL_pallets", 0))
    totals["TSI_units"] = (totals.get("TSI_PAX_quantity", 0) + totals.get("TSI_MIX_SELLABLE_quantity", 0) + totals.get("TSI_WRO1_SELL_quantity", 0) + totals.get("TSI_MIX_UNSELL_quantity", 0))
    totals["FBA_units"] = totals.get("NVF_SB_quantity", 0)
    totals["OC_units"] = totals.get("NVF_OC_quantity", 0)
    totals["SB"] = totals.get("SB_pallets_total", 0)
    
    all_keys = ["OC_count", "ROTOM_count", "ATS_count", "CARRIER_count", "SB_pallets_total", "NVF_PP_pallets", "NVF_PP_quantity", "NVF_MIX_pallets", "NVF_MIX_quantity", "NVF_OC_pallets", "NVF_OC_quantity", "NVF_SB_pallets", "NVF_SB_quantity", "NVF_TOTAL_DISPLAY", "TSI_PAX_pallets", "TSI_PAX_quantity", "TSI_MIX_SELLABLE_pallets", "TSI_MIX_SELLABLE_quantity", "TSI_WRO1_SELL_pallets", "TSI_WRO1_SELL_quantity", "TSI_MIX_UNSELL_pallets", "TSI_MIX_UNSELL_quantity", "TSI_TOTAL_DISPLAY", "PAX_NVF_PP_pallets", "PAX_NVF_PP_quantity", "PAX_TSI_PAX_pallets", "PAX_TSI_PAX_quantity", "PAX_FBA_pallets", "PAX_FBA_quantity", "PAX_OC_pallets", "PAX_OC_quantity", "PAX_CC_pallets", "PAX_CC_quantity", "PAX_KARMA_pallets", "PAX_KARMA_quantity", "PAX_TOTAL_DISPLAY", "MIX_BACKLOG_NVF_pallets", "MIX_BACKLOG_NVF_quantity", "MIX_BACKLOG_TSI_pallets", "MIX_BACKLOG_TSI_quantity", "MIX_WRO1_SELL_pallets", "MIX_WRO1_SELL_quantity", "MIX_UNSELL_pallets", "MIX_UNSELL_quantity", "MIX_FBA_pallets", "MIX_FBA_quantity", "MIX_OC_pallets", "MIX_OC_quantity", "MIX_TOTAL_DISPLAY", "SPECIAL_TL_pallets", "SPECIAL_TL_quantity", "SPECIAL_HV_pallets", "SPECIAL_HV_quantity", "SPECIAL_CAGE_pallets", "SPECIAL_CAGE_quantity", "SPECIAL_PREP_pallets", "SPECIAL_PREP_quantity", "SPECIAL_OVERSIZE_pallets", "SPECIAL_OVERSIZE_quantity", "DOCK_NVF_PALLETS", "DOCK_TSI_PALLETS", "DOCK_TOTAL_PALLETS", "DOCK_FULLNESS_PERCENTAGE", "TOTAL_BACKLOG_DISPLAY", "NVF_units", "TSI_units", "FBA_units", "OC_units", "SB", "NVF_pallets", "TSI_pallets", "CC_units", "UNVERIFIED_SB_pallets", "UNVERIFIED_SB_quantity", "UNVERIFIED_CC_pallets", "UNVERIFIED_CC_quantity", "UNVERIFIED_TOTAL_DISPLAY"]
    for key in all_keys:
        if key not in totals or totals[key] is None:
            totals[key] = 0

    return totals

def calculate_totals_from_deleted(deleted_stocks_queryset):
    """
    Zoptymalizowana i POPRAWIONA wersja funkcji dla usuniętych stocków.
    """
    totals = {
        "OC_count": 0, "ROTOM_count": 0, "ATS_count": 0, "CARRIER_count": 0, "SB_pallets_total": 0,
        "NVF_PP_pallets": 0, "NVF_PP_quantity": 0, "NVF_MIX_pallets": 0, "NVF_MIX_quantity": 0,
        "NVF_OC_pallets": 0, "NVF_OC_quantity": 0, "NVF_SB_pallets": 0, "NVF_SB_quantity": 0,
        "NVF_TOTAL_DISPLAY": 0,
        "TSI_PAX_pallets": 0, "TSI_PAX_quantity": 0, "TSI_MIX_SELLABLE_pallets": 0, "TSI_MIX_SELLABLE_quantity": 0,
        "TSI_WRO1_SELL_pallets": 0, "TSI_WRO1_SELL_quantity": 0, "TSI_MIX_UNSELL_pallets": 0, "TSI_MIX_UNSELL_quantity": 0,
        "TSI_TOTAL_DISPLAY": 0,
        "PAX_NVF_PP_pallets": 0, "PAX_NVF_PP_quantity": 0, "PAX_TSI_PAX_pallets": 0, "PAX_TSI_PAX_quantity": 0,
        "PAX_FBA_pallets": 0, "PAX_FBA_quantity": 0, "PAX_OC_pallets": 0, "PAX_OC_quantity": 0,
        "PAX_CC_pallets": 0, "PAX_CC_quantity": 0,
        "PAX_KARMA_pallets": 0, "PAX_KARMA_quantity": 0,
        "PAX_TOTAL_DISPLAY": 0,
        "MIX_BACKLOG_NVF_pallets": 0, "MIX_BACKLOG_NVF_quantity": 0, "MIX_BACKLOG_TSI_pallets": 0, "MIX_BACKLOG_TSI_quantity": 0,
        "MIX_WRO1_SELL_pallets": 0, "MIX_WRO1_SELL_quantity": 0, "MIX_UNSELL_pallets": 0, "MIX_UNSELL_quantity": 0,
        "MIX_FBA_pallets": 0, "MIX_FBA_quantity": 0, "MIX_OC_pallets": 0, "MIX_OC_quantity": 0,
        "MIX_TOTAL_DISPLAY": 0,
        "SPECIAL_TL_pallets": 0, "SPECIAL_TL_quantity": 0, "SPECIAL_HV_pallets": 0, "SPECIAL_HV_quantity": 0,
        "SPECIAL_CAGE_pallets": 0, "SPECIAL_CAGE_quantity": 0, "SPECIAL_PREP_pallets": 0, "SPECIAL_PREP_quantity": 0,
        "SPECIAL_OVERSIZE_pallets": 0, "SPECIAL_OVERSIZE_quantity": 0,
        "DOCK_NVF_PALLETS": 0, "DOCK_TSI_PALLETS": 0, "DOCK_TOTAL_PALLETS": 0, "DOCK_FULLNESS_PERCENTAGE": 0,
        "TOTAL_BACKLOG_DISPLAY": 0,
        "NVF_units": 0, "TSI_units": 0, "FBA_units": 0, "OC_units": 0, "SB": 0,
        "NVF_pallets": 0, "TSI_pallets": 0,
        "CC_units": 0,
        "UNVERIFIED_SB_pallets": 0, "UNVERIFIED_SB_quantity": 0,
        "UNVERIFIED_CC_pallets": 0, "UNVERIFIED_CC_quantity": 0,
        "UNVERIFIED_TOTAL_DISPLAY": 0,
    }

    for stock_record in deleted_stocks_queryset:
        try:
            data = stock_record.original_stock_data
            comment = (data.get('comment', '') or "").lower()

            is_d2d_tag = "#d2d#" in comment
            is_oc_tag = "#oc#" in comment
            is_rotom_tag = "#rotom#" in comment
            is_ats_tag = "#ats#" in comment
            is_carrier_tag = "#carrier#" in comment
            stock_isa = data.get('ISA')
            sb_p = data.get('SB', 0) or 0

            # Poprawiona logika zliczania - liczniki PRZED pominięciem #d2d#
            if is_rotom_tag and stock_isa and str(stock_isa).strip() and int(stock_isa) != 0:
                totals["ROTOM_count"] += 1
            if is_oc_tag: totals["OC_count"] += 1
            if is_ats_tag: totals["ATS_count"] += 1
            if is_carrier_tag: totals["CARRIER_count"] += 1
            
            # Suma SB jest liczona niezależnie od #d2d# w oryginalnym kodzie
            totals["SB_pallets_total"] += sb_p

            if is_d2d_tag:
                continue

            # Reszta obliczeń, która ignoruje #d2d#
            nvfpp_p = data.get('NVFPP', 0) or 0
            nvfpp_q = data.get('NVF', 0) or 0
            nvf_mix_p = data.get('NVF_MIX', 0) or 0
            nvf_mix_q = data.get('MIX', 0) or 0
            tsi_pax_p = data.get('TSI_PAX', 0) or 0
            tsi_pax_q = data.get('TSI', 0) or 0
            tsi_mix_p = data.get('TSI_MIX_P', 0) or 0
            tsi_mix_q = data.get('TSI_MIX_U', 0) or 0
            sb_q = data.get('FBA', 0) or 0

            totals["TOTAL_BACKLOG_DISPLAY"] += (nvfpp_q + nvf_mix_q + sb_q + tsi_pax_q + tsi_mix_q)

            tags_found = re.findall(r'#([^#]+)#', comment)
            comment_tags = {tag.strip() for tag in tags_found}

            is_unverified_sb_combo = comment_tags in [
                {'do sprawdzenia'},
                {'do sprawdzenia', 'deutp'},
                {'do sprawdzenia', 'slamd'}
            ]
            is_unverified_cc_combo = (comment_tags == {'carrier', 'do sprawdzenia'})

            if is_unverified_sb_combo or is_unverified_cc_combo:
                totals["UNVERIFIED_SB_pallets"] += sb_p
                totals["UNVERIFIED_SB_quantity"] += sb_q
                totals["UNVERIFIED_CC_pallets"] += nvfpp_p + nvf_mix_p
                totals["UNVERIFIED_CC_quantity"] += nvfpp_q + nvf_mix_q

            line = (data.get('line', '') or "").lower()
            is_unsell_tag = "#unsell#" in comment
            is_wro1_sell_tag = "#wro1_sell#" in comment
            is_mix_tag = "#mix#" in comment
            is_pax_tag = "#pax#" in comment
            is_ll_pax_tag = "#ll pax#" in comment
            is_tl_tag = "#tl#" in comment
            is_hv_tag = "#hv#" in comment
            is_cage_tag = "#cage#" in comment
            is_prep_tag = "#prep#" in comment
            is_oversize_tag = "#oversize#" in comment
            is_dock = "dock" in line
            is_karma_tag = "#karma#" in comment

            if is_carrier_tag:
                totals["CC_units"] += nvfpp_q + nvf_mix_q + tsi_pax_q + tsi_mix_q
            if not is_oc_tag:
                totals["NVF_PP_pallets"] += nvfpp_p
                totals["NVF_PP_quantity"] += nvfpp_q
                totals["NVF_MIX_pallets"] += nvf_mix_p
                totals["NVF_MIX_quantity"] += nvf_mix_q
            if is_oc_tag:
                totals["NVF_OC_quantity"] += nvfpp_q + nvf_mix_q
            totals["NVF_SB_quantity"] += sb_q
            totals["TSI_PAX_pallets"] += tsi_pax_p
            totals["TSI_PAX_quantity"] += tsi_pax_q
            if is_unsell_tag:
                totals["TSI_MIX_UNSELL_pallets"] += tsi_mix_p
                totals["TSI_MIX_UNSELL_quantity"] += tsi_mix_q
            elif is_wro1_sell_tag:
                totals["TSI_WRO1_SELL_pallets"] += tsi_mix_p
                totals["TSI_WRO1_SELL_quantity"] += tsi_mix_q
            else:
                totals["TSI_MIX_SELLABLE_pallets"] += tsi_mix_p
                totals["TSI_MIX_SELLABLE_quantity"] += tsi_mix_q
            if is_pax_tag and not is_oc_tag and not is_karma_tag:
                totals["PAX_NVF_PP_pallets"] += nvfpp_p
                totals["PAX_NVF_PP_quantity"] += nvfpp_q
            if is_pax_tag and not is_karma_tag:
                totals["PAX_TSI_PAX_pallets"] += tsi_pax_p
                totals["PAX_TSI_PAX_quantity"] += tsi_pax_q
            if is_ll_pax_tag:
                totals["PAX_FBA_pallets"] += sb_p
                totals["PAX_FBA_quantity"] += sb_q
                if is_oc_tag:
                    totals["PAX_OC_pallets"] += nvfpp_p + nvf_mix_p
                    totals["PAX_OC_quantity"] += nvfpp_q + nvf_mix_q
                if is_carrier_tag:
                    totals["PAX_CC_pallets"] += nvfpp_p + nvf_mix_p
                    totals["PAX_CC_quantity"] += nvfpp_q + nvf_mix_q
            if is_karma_tag:
                totals["PAX_KARMA_pallets"] += nvfpp_p + tsi_pax_p
                totals["PAX_KARMA_quantity"] += nvfpp_q + tsi_pax_q
            if is_mix_tag and not is_oc_tag:
                totals["MIX_BACKLOG_NVF_pallets"] += nvf_mix_p
                totals["MIX_BACKLOG_NVF_quantity"] += nvf_mix_q
            if is_mix_tag:
                if not is_unsell_tag and not is_wro1_sell_tag:
                     totals["MIX_BACKLOG_TSI_pallets"] += tsi_mix_p
                     totals["MIX_BACKLOG_TSI_quantity"] += tsi_mix_q
                totals["MIX_FBA_pallets"] += sb_p
                totals["MIX_FBA_quantity"] += sb_q
                if is_oc_tag:
                     totals["MIX_OC_pallets"] += nvfpp_p + nvf_mix_p
                     totals["MIX_OC_quantity"] += nvfpp_q + nvf_mix_q
            if is_wro1_sell_tag:
                 totals["MIX_WRO1_SELL_pallets"] += tsi_mix_p
                 totals["MIX_WRO1_SELL_quantity"] += tsi_mix_q
            if is_unsell_tag:
                 totals["MIX_UNSELL_pallets"] += tsi_mix_p
                 totals["MIX_UNSELL_quantity"] += tsi_mix_q
            current_pallets_for_special_del = nvfpp_p + nvf_mix_p + tsi_pax_p + tsi_mix_p + sb_p
            current_quantity_for_special_del = nvfpp_q + nvf_mix_q + tsi_pax_q + tsi_mix_q + sb_q
            if is_tl_tag: totals["SPECIAL_TL_pallets"] += current_pallets_for_special_del; totals["SPECIAL_TL_quantity"] += current_quantity_for_special_del
            if is_hv_tag: totals["SPECIAL_HV_pallets"] += current_pallets_for_special_del; totals["SPECIAL_HV_quantity"] += current_quantity_for_special_del
            if is_cage_tag: totals["SPECIAL_CAGE_pallets"] += current_pallets_for_special_del; totals["SPECIAL_CAGE_quantity"] += current_quantity_for_special_del
            if is_prep_tag: totals["SPECIAL_PREP_pallets"] += current_pallets_for_special_del; totals["SPECIAL_PREP_quantity"] += current_quantity_for_special_del
            if is_oversize_tag: totals["SPECIAL_OVERSIZE_pallets"] += current_pallets_for_special_del; totals["SPECIAL_OVERSIZE_quantity"] += current_quantity_for_special_del
            if is_dock:
                totals["DOCK_NVF_PALLETS"] += nvfpp_p + nvf_mix_p
                totals["DOCK_TSI_PALLETS"] += tsi_pax_p + tsi_mix_p
                totals["DOCK_TOTAL_PALLETS"] += current_pallets_for_special_del
        except Exception as e_calc_del:
             logger.error(f"Error calculating totals for deleted stock record ID {stock_record.id}: {e_calc_del}", exc_info=True)
             continue
    
    # Końcowe sumowanie
    totals["NVF_OC_pallets"] = totals["OC_count"]
    totals["NVF_SB_pallets"] = totals["SB_pallets_total"]
    totals["NVF_TOTAL_DISPLAY"] = totals["NVF_PP_quantity"] + totals["NVF_MIX_quantity"] + totals["NVF_OC_quantity"] + totals["NVF_SB_quantity"]
    totals["TSI_TOTAL_DISPLAY"] = totals["TSI_PAX_quantity"] + totals["TSI_MIX_SELLABLE_quantity"] + totals["TSI_WRO1_SELL_quantity"] + totals["TSI_MIX_UNSELL_quantity"]
    totals["PAX_TOTAL_DISPLAY"] = (totals["PAX_NVF_PP_quantity"] + totals["PAX_TSI_PAX_quantity"] + totals["PAX_FBA_quantity"] + totals["PAX_OC_quantity"] + totals["PAX_CC_quantity"] + totals["PAX_KARMA_quantity"])
    totals["MIX_TOTAL_DISPLAY"] = (totals["MIX_BACKLOG_NVF_quantity"] + totals["MIX_BACKLOG_TSI_quantity"] + totals["MIX_WRO1_SELL_quantity"] + totals["MIX_UNSELL_quantity"] + totals["MIX_FBA_quantity"] + totals["MIX_OC_quantity"])
    totals["UNVERIFIED_TOTAL_DISPLAY"] = totals["UNVERIFIED_SB_quantity"] + totals["UNVERIFIED_CC_quantity"]
    max_dock_pallets = 800
    totals["DOCK_FULLNESS_PERCENTAGE"] = (totals["DOCK_TOTAL_PALLETS"] / max_dock_pallets) * 100 if max_dock_pallets > 0 else 0
    totals["DOCK_FULLNESS_PERCENTAGE"] = min(totals["DOCK_FULLNESS_PERCENTAGE"], 100)
    totals["NVF_pallets"] = totals["NVF_PP_pallets"] + totals["NVF_MIX_pallets"]
    totals["NVF_units"] = totals["NVF_PP_quantity"] + totals["NVF_MIX_quantity"]
    totals["TSI_pallets"] = totals["TSI_PAX_pallets"] + totals["TSI_MIX_SELLABLE_pallets"] + totals["TSI_WRO1_SELL_pallets"] + totals["TSI_MIX_UNSELL_pallets"]
    totals["TSI_units"] = totals["TSI_PAX_quantity"] + totals["TSI_MIX_SELLABLE_quantity"] + totals["TSI_WRO1_SELL_quantity"] + totals["TSI_MIX_UNSELL_quantity"]
    totals["FBA_units"] = totals["NVF_SB_quantity"]
    totals["OC_units"] = totals["NVF_OC_quantity"]
    totals["SB"] = totals["SB_pallets_total"]

    return totals
# ----------------------------------------------------------------------------------
# KONIEC SEKCJI ZOPTYMALIZOWANEJ
# ----------------------------------------------------------------------------------


# === Widoki zarządzania stockiem ===

def parse_datetime_string(datetime_str):
    if not datetime_str:
        return None

    formats = [
        "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S",
        "%d.%m.%Y %H:%M", "%d.%m.%Y %H:%M:%S",
        "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M", "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M", "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M", "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S",
        "%d %b %Y %H:%M", "%d %B %Y %H:%M",
        "%b %d %Y %H:%M", "%B %d %Y %H:%M",
    ]

    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(datetime_str, fmt)
            if settings.USE_TZ and timezone.is_naive(dt):
                return timezone.make_aware(dt, timezone.get_default_timezone())
            return dt
        except ValueError:
            continue

    logger.warning(f"Could not parse manual date string: '{datetime_str}' using known formats.")
    return None

@login_required
def add_stock(request):
    range_102_123 = range(102, 124)
    range_01_28 = range(1, 29)

    if request.method == 'POST':
        form = StockForm(request.POST)
        if form.is_valid():
            try:
                stock = form.save(commit=False)
                stock.user = request.user.username
                stock.last_edited_by = request.user.username

                manual_input_str = form.cleaned_data.get('sbd_sla_manual_input')
                parsed_manual_date = parse_datetime_string(manual_input_str)

                if parsed_manual_date:
                    stock.start_time = parsed_manual_date
                    stock.sbd_sla_manual_input = manual_input_str
                    logger.info(f"Using manually parsed SBD/SLA for stock ISA {stock.ISA}: {parsed_manual_date}")
                else:
                    stock.start_time = form.cleaned_data.get('start_time')
                    stock.sbd_sla_manual_input = None
                    if manual_input_str:
                         logger.warning(f"Manual SBD/SLA parsing failed for '{manual_input_str}'. Falling back to standard field for stock ISA {stock.ISA}.")
                    else:
                         logger.info(f"Using standard SBD/SLA field for stock ISA {stock.ISA}.")

                if stock.start_time is None:
                     logger.error(f"Critical: start_time is None for stock ISA {stock.ISA} after processing inputs. Check form validation and parsing logic.")
                     messages.error(request, 'Nie udało się ustawić daty SBD/SLA. Sprawdź wpisane wartości.')

                stock.save()

                if stock.line.upper() in ROTOM_IDS_UPPER:
                    RotomHistory.objects.create(
                        trailer_id=stock.line.upper(),
                        event_type='ADDED',
                        event_timestamp=stock.created_at or timezone.now(),
                        user=stock.user,
                        isa=stock.ISA,
                        details=f"Added to line '{stock.line}' with comment: '{stock.comment or 'N/A'}'"
                    )

                logger.info(f"Stock ISA {stock.ISA} added by user {request.user.username}.")
                messages.success(request, 'Stock added successfully!')
                return redirect('stock_list')

            except Exception as e:
                logger.error(f"Error saving stock added by {request.user.username}: {str(e)}", exc_info=True)
                messages.error(request, f'Błąd podczas zapisywania stocku: {e}. Proszę spróbować ponownie.')
        else:
            logger.warning(f"Invalid stock form submitted by {request.user.username}. Errors: {form.errors.as_json()}")
            error_list = "<ul>"; [error_list := error_list + f"<li>{field}: {', '.join(errors)}</li>" for field, errors in form.errors.items()]; error_list += "</ul>"
            messages.error(request, f'Proszę poprawić błędy w formularzu: {error_list}', extra_tags='safe')
    else:
        form = StockForm()

    context = {
        'form': form,
        'app_version': settings.APP_VERSION,
        'range_102_123': range_102_123,
        'range_01_28': range_01_28
    }
    return render(request, 'dock_nyr_add.html', context)


@login_required
def edit_stock(request, stock_id):
    range_102_123 = range(102, 124)
    range_01_28 = range(1, 29)
    stock = get_object_or_404(Stock, pk=stock_id)

    if not request.user.has_perm('dock_nyr.change_stock'):
         logger.warning(f"User {request.user.username} attempted to edit stock {stock_id} without permission.")
         messages.error(request, "Nie masz uprawnień do edycji tego stocku.")
         return redirect('stock_list')

    if request.method == 'POST':
        form = StockForm(request.POST, instance=stock)
        if form.is_valid():
            try:
                edited_stock = form.save(commit=False)
                edited_stock.last_edited_by = request.user.username

                manual_input_str = form.cleaned_data.get('sbd_sla_manual_input')
                parsed_manual_date = parse_datetime_string(manual_input_str)

                if parsed_manual_date:
                    edited_stock.start_time = parsed_manual_date
                    edited_stock.sbd_sla_manual_input = manual_input_str
                    logger.info(f"Using manually parsed SBD/SLA for updating stock ISA {edited_stock.ISA}: {parsed_manual_date}")
                else:
                    edited_stock.start_time = form.cleaned_data.get('start_time')
                    edited_stock.sbd_sla_manual_input = None
                    if manual_input_str:
                         logger.warning(f"Manual SBD/SLA parsing failed for '{manual_input_str}' during edit. Falling back to standard field for stock ISA {edited_stock.ISA}.")
                    else:
                         logger.info(f"Using standard SBD/SLA field for updating stock ISA {edited_stock.ISA}.")

                if edited_stock.start_time is None:
                    logger.error(f"Critical: start_time is None for stock ISA {edited_stock.ISA} after processing inputs during edit.")
                    messages.error(request, 'Nie udało się ustawić daty SBD/SLA podczas edycji. Sprawdź wpisane wartości.')

                edited_stock.save()

                if edited_stock.line.upper() in ROTOM_IDS_UPPER:
                    RotomHistory.objects.create(
                        trailer_id=edited_stock.line.upper(),
                        event_type='EDITED',
                        event_timestamp=timezone.now(),
                        user=request.user.username,
                        isa=edited_stock.ISA,
                        details=f"Stock entry updated. Comment: '{edited_stock.comment or 'N/A'}'"
                    )

                logger.info(f"Stock {stock_id} updated by user {request.user.username}.")
                messages.success(request, 'Stock updated successfully!')
                return redirect('stock_list')

            except Exception as e:
                logger.error(f"Error updating stock {stock_id} by {request.user.username}: {str(e)}", exc_info=True)
                messages.error(request, f'Błąd podczas aktualizacji stocku: {e}. Proszę spróbować ponownie.')
        else:
             logger.warning(f"Invalid stock edit form for ID {stock_id} by {request.user.username}. Errors: {form.errors.as_json()}")
             error_list = "<ul>"; [error_list := error_list + f"<li>{field}: {', '.join(errors)}</li>" for field, errors in form.errors.items()]; error_list += "</ul>"
             messages.error(request, f'Proszę poprawić błędy w formularzu: {error_list}', extra_tags='safe')
    else:
        form = StockForm(instance=stock)
        if 'user' in form.fields:
             form.fields['user'].widget.attrs['readonly'] = True
             form.fields['user'].widget.attrs['disabled'] = True

    context = {
        'form': form,
        'stock': stock,
        'app_version': settings.APP_VERSION,
        'range_102_123': range_102_123,
        'range_01_28': range_01_28
    }
    return render(request, 'dock_nyr_edit.html', context)


@login_required
def delete_stock(request, stock_id):
    stock = get_object_or_404(Stock, pk=stock_id)
    if not request.user.has_perm('dock_nyr.delete_stock'):
         logger.warning(f"User {request.user.username} attempted to delete stock {stock_id} without permission.")
         messages.error(request, "Nie masz uprawnień do usunięcia tego stocku.")
         return redirect('stock_list')
    if request.method == 'POST':
        try:
            if stock.line.upper() in ROTOM_IDS_UPPER:
                RotomHistory.objects.create(
                    trailer_id=stock.line.upper(),
                    event_type='DELETED',
                    event_timestamp=timezone.now(),
                    user=request.user.username,
                    isa=stock.ISA,
                    details=f"Deleted from line '{stock.line}'"
                )

            now = timezone.now()
            sbd_color_status = 'none'
            if stock.start_time:
                start_time_aware = timezone.make_aware(stock.start_time, timezone.get_default_timezone()) if timezone.is_naive(stock.start_time) else stock.start_time
                time_diff = start_time_aware - now
                if time_diff.total_seconds() < 0: sbd_color_status = 'red'
                elif 0 <= time_diff.total_seconds() <= 6 * 3600: sbd_color_status = 'yellow'

            stock_data = {
                'ISA': stock.ISA, 'user': stock.user, 'last_edited_by': stock.last_edited_by,
                'last_edited_at': stock.last_edited_at.isoformat() if stock.last_edited_at else None,
                'created_at': stock.created_at.isoformat() if stock.created_at else None,
                'NVFPP': stock.NVFPP, 'NVF': stock.NVF, 'NVF_MIX': stock.NVF_MIX, 'MIX': stock.MIX,
                'TSI_PAX': stock.TSI_PAX, 'TSI': stock.TSI, 'TSI_MIX_P': stock.TSI_MIX_P, 'TSI_MIX_U': stock.TSI_MIX_U,
                'SB': stock.SB, 'FBA': stock.FBA,
                'start_time': stock.start_time.isoformat() if stock.start_time else None,
                'sbd_sla_manual_input': stock.sbd_sla_manual_input,
                'line': stock.line, 'comment': stock.comment, 'delay': stock.delay,
                'sbd_sla_color_status': sbd_color_status
            }

            DeletedStock.objects.create(original_stock_data=stock_data, deleted_at=now, deleted_by=request.user.username)
            stock_isa = stock.ISA
            stock.delete()
            logger.info(f"Stock ISA {stock_isa} (ID: {stock_id}) deleted by user {request.user.username} and moved to summary. SBD/SLA status: {sbd_color_status}.")
            messages.success(request, f'Stock {stock_isa} deleted successfully and moved to summary.')
            return redirect('stock_list')

        except Exception as e:
            logger.error(f"Error deleting stock {stock_id} by {request.user.username}: {str(e)}", exc_info=True)
            messages.error(request, 'Błąd podczas usuwania stocku. Proszę spróbować ponownie.')
            return redirect('stock_list')

    context = {'stock': stock, 'app_version': settings.APP_VERSION}
    return render(request, 'dock_nyr_delete.html', context)


@login_required
@require_POST
def quick_add_stock(request):
    try:
        data = json.loads(request.body)
        isa = data.get('isa')
        line = data.get('line')
        start_time_str = data.get('start_time')
        comment = data.get('comment', '')

        if not isa or not line or not start_time_str:
            return JsonResponse({'success': False, 'error': 'Missing ISA, Line/ID, or Start Time.'}, status=400)

        try: isa_int = int(isa)
        except ValueError: return JsonResponse({'success': False, 'error': 'Invalid ISA number format.'}, status=400)

        try:
            start_time_dt = datetime.datetime.fromisoformat(start_time_str)
            if settings.USE_TZ: start_time_dt = timezone.make_aware(start_time_dt, timezone.get_default_timezone())
        except ValueError: return JsonResponse({'success': False, 'error': 'Invalid date/time format. Use YYYY-MM-DDTHH:MM.'}, status=400)

        new_stock = Stock(
            ISA=isa_int, line=line, start_time=start_time_dt, comment=comment,
            SB=1, FBA=450,
            user=request.user.username, last_edited_by=request.user.username,
        )
        new_stock.save()
        logger.info(f"Quick Add: Stock ISA {new_stock.ISA}, Line {new_stock.line} added by user {request.user.username}.")
        return JsonResponse({'success': True})

    except json.JSONDecodeError:
        logger.warning(f"Quick Add: Invalid JSON received from user {request.user.username}.")
        return JsonResponse({'success': False, 'error': 'Invalid JSON data.'}, status=400)
    except IntegrityError as e:
        logger.error(f"Quick Add: Integrity error for user {request.user.username}. ISA: {data.get('isa')}, Line: {data.get('line')}. Error: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': f'Database integrity error: {e}'}, status=400)
    except Exception as e:
        logger.error(f"Quick Add: Error processing request for user {request.user.username}. ISA: {data.get('isa')}, Line: {data.get('line')}. Error: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': f'An unexpected error occurred: {e}'}, status=500)

@login_required
def rotom_list(request):
    rotom_trailers_data = []
    now = timezone.now()

    for trailer_id in ROTOM_IDS:
        stock_item = Stock.objects.filter(line__icontains=trailer_id).order_by('-last_edited_at').first()

        if stock_item:
            dwell_time_str = 'N/A'
            dwell_status = 'n_a'
            dwell_seconds = float('-inf')

            if stock_item.start_time:
                start_time_aware = stock_item.start_time
                if timezone.is_naive(start_time_aware):
                    start_time_aware = timezone.make_aware(start_time_aware, timezone.get_default_timezone())

                if now > start_time_aware:
                    time_diff = now - start_time_aware
                    dwell_status = 'overdue'
                    dwell_seconds = time_diff.total_seconds()
                    prefix = 'Overdue by: '
                else:
                    time_diff = start_time_aware - now
                    dwell_status = 'counting_down'
                    dwell_seconds = -time_diff.total_seconds()
                    prefix = 'Time left: '

                days = time_diff.days
                hours, remainder = divmod(time_diff.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                dwell_time_str = f"{prefix}{days}d {hours}h {minutes}m"

            last_edited_str = "N/A"
            if stock_item.last_edited_by and stock_item.last_edited_at:
                try:
                    local_last_edited_at = timezone.localtime(stock_item.last_edited_at)
                    formatted_time = local_last_edited_at.strftime('%Y-%m-%d %H:%M')
                    last_edited_str = f"{stock_item.last_edited_by} at {formatted_time}"
                except Exception:
                    last_edited_str = stock_item.last_edited_by
            elif stock_item.last_edited_by:
                last_edited_str = stock_item.last_edited_by

            rotom_trailers_data.append({
                'id': trailer_id,
                'dwell_time': dwell_time_str,
                'dwell_status': dwell_status,
                'dwell_seconds': dwell_seconds,
                'content': stock_item,
                'last_edited': last_edited_str,
            })
        else:
            rotom_trailers_data.append({
                'id': trailer_id,
                'dwell_time': 'N/A',
                'dwell_status': 'empty',
                'dwell_seconds': float('-inf'),
                'content': 'empty',
                'last_edited': 'N/A',
            })

    rotom_trailers_data.sort(key=lambda x: x['dwell_seconds'], reverse=True)

    for index, trailer in enumerate(rotom_trailers_data, 1):
        trailer['no'] = index

    context = {
        'rotom_trailers': rotom_trailers_data,
        'user': request.user,
        'app_version': settings.APP_VERSION,
    }
    return render(request, 'rotom_list.html', context)

@login_required
@require_GET
def rotom_history(request, trailer_id):
    """
    Pobiera i zwraca chronologiczną historię zdarzeń dla danego ID naczepy ROTOM
    z dedykowanej, trwałej tabeli RotomHistory.
    """
    try:
        history_events = RotomHistory.objects.filter(trailer_id__iexact=trailer_id).order_by('-event_timestamp')

        history_data = [
            {
                'event_type': event.event_type,
                'timestamp': timezone.localtime(event.event_timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'isa': event.isa,
                'user': event.user,
                'details': event.details,
            }
            for event in history_events
        ]

        return JsonResponse({'history': history_data})
    except Exception as e:
        logger.error(f"Error fetching ROTOM history for {trailer_id}: {e}", exc_info=True)
        return JsonResponse({'error': 'Failed to fetch history.'}, status=500)