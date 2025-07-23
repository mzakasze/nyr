from django import forms
from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Stock
from django.utils import timezone

class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=False,
        label='Email (optional)',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Optional email'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Customize form fields
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Password',
            'autocomplete': 'new-password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm Password',
            'autocomplete': 'new-password'
        })
        # Remove help texts
        self.fields['password1'].help_text = ''
        self.fields['password2'].help_text = ''

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']
        help_texts = {
            'username': '',
        }

class StockForm(ModelForm):
    # Definiujemy pole 'user', aby móc ustawić je jako disabled w __init__
    user = forms.CharField(
        required=False,
        disabled=True, # Domyślnie ustawiamy jako disabled
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            #'readonly': 'readonly' # Disabled jest wystarczające
        })
    )

    # <<< NOWE POLE W FORMULARZU >>>
    sbd_sla_manual_input = forms.CharField(
        label="Manual SBD/SLA Input",
        required=False, # Nie jest wymagane, można użyć auto-daty
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter date/time freely'
        }),
        help_text="Overrides the standard SBD/SLA field if filled."
    )
    # <<< KONIEC NOWEGO POLA W FORMULARZU >>>

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Ustawiamy początkową wartość pola 'user' na podstawie instancji (jeśli edytujemy)
        # I upewniamy się, że jest disabled
        if self.instance and self.instance.pk:
            user_value = getattr(self.instance, 'user', None)
            if user_value:
                 self.fields['user'].initial = user_value

            last_edited_by_val = getattr(self.instance, 'last_edited_by', None)
            last_edited = f"Last edited by: {last_edited_by_val}" if last_edited_by_val else ""
            self.fields['user'].widget.attrs.update({
                'title': last_edited,
                'class': 'form-control with-tooltip',
            })
            self.fields['user'].disabled = True # Upewniamy się, że jest disabled

            # Wypełnij pole manualnego wprowadzania, jeśli istnieje w instancji
            manual_input_value = getattr(self.instance, 'sbd_sla_manual_input', None)
            if manual_input_value:
                self.fields['sbd_sla_manual_input'].initial = manual_input_value

        else:
            # Jeśli tworzymy nowy stock, pole 'user' nie jest potrzebne w formularzu
             pass # Pozostawiamy disabled

        # Ustawiamy pole start_time jako nieobowiązkowe
        self.fields['start_time'].required = False

    class Meta:
        model = Stock
        # Wykluczamy pola automatyczne. 'user' jest obsługiwane w __init__.
        # 'sbd_sla_manual_input' jest dodane jawnie powyżej, więc nie musi być tu.
        exclude = ['last_edited_by', 'last_edited_at', 'created_at']

        # Można też jawnie wymienić pola, upewniając się, że jest `sbd_sla_manual_input`
        # fields = ['ISA', 'NVFPP', 'NVF', 'NVF_MIX', 'MIX', 'TSI_PAX', 'TSI',
        #           'TSI_MIX_P', 'TSI_MIX_U', 'SB', 'FBA', 'start_time',
        #           'sbd_sla_manual_input', # Upewnij się, że jest tutaj
        #           'line', 'comment', 'delay']


        labels = {
            'ISA': 'ISA Number',
            'NVFPP': 'NVF PP',
            'NVF': 'NVF Units',
            'NVF_MIX': 'NVF MIX',
            'MIX': 'MIX Units',
            'TSI_PAX': 'TSI PAX',
            'TSI': 'TSI Units',
            'TSI_MIX_P': 'TSI MIX P',
            'TSI_MIX_U': 'TSI MIX U',
            'SB': 'SB',
            'FBA': 'FBA Units',
            'line': 'Line',
            'comment': 'Comments',
            'delay': 'Delay Reason',
            'start_time': "SBD/SLA",
            # Etykieta dla sbd_sla_manual_input jest zdefiniowana powyżej
        }
        help_texts = {
            'ISA': 'Enter the ISA number',
            'start_time': 'Auto-populates, overridden by manual input.', # Uaktualniono format
            'line': 'Enter production line identifier (e.g., IB 102, DOCK 05)',
             # Help text dla sbd_sla_manual_input jest zdefiniowany powyżej
        }
        widgets = {
            # MODIFIED: Removed placeholders
            'comment': forms.Textarea(attrs={
                'rows': 3
            }),
            'delay': forms.Textarea(attrs={
                'rows': 3
            }),
             # Używamy DateTimeInput dla standardowego pola, ale nie jest ono już wymagane
             'start_time': forms.DateTimeInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
             # Widget dla sbd_sla_manual_input jest zdefiniowany powyżej
        }