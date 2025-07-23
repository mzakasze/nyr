# dock_nyr/models.py
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

class Stock(models.Model):
    ISA = models.IntegerField(verbose_name="ISA Number")

    user = models.CharField(
        verbose_name="User",
        max_length=50,
        blank=True # Pole użytkownika, który pierwotnie dodał
    )
    last_edited_by = models.CharField(max_length=50, blank=True) # Użytkownik, który ostatnio edytował
    last_edited_at = models.DateTimeField(auto_now=True, null=True, blank=True) # Czas ostatniej edycji
    created_at = models.DateTimeField(
        auto_now_add=True, # Automatycznie ustawia czas przy tworzeniu
        null=True,         # Pozwala na NULL dla istniejących rekordów przed migracją
        verbose_name="Created At" # NOWE POLE: Czas utworzenia rekordu
    )

    # NVF related fields
    NVFPP = models.IntegerField(
        verbose_name="NVF PP",
        null=True,
        blank=True,
        help_text="Number of NVF pallets"
    )
    NVF = models.IntegerField(
        verbose_name="NVF Units",
        null=True,
        blank=True,
        help_text="Number of NVF units"
    )
    NVF_MIX = models.IntegerField(
        verbose_name="NVF MIX Pallets",
        null=True,
        blank=True,
        help_text="Number of NVF mixed pallets"
    )
    MIX = models.IntegerField(
        verbose_name="MIX Units",
        null=True,
        blank=True,
        help_text="Number of mixed units"
    )

    # TSI related fields
    TSI_PAX = models.IntegerField(
        verbose_name="TSI PAX",
        null=True,
        blank=True,
        help_text="Number of TSI pallets"
    )
    TSI = models.IntegerField(
        verbose_name="TSI Units",
        null=True,
        blank=True,
        help_text="Number of TSI units"
    )
    TSI_MIX_P = models.IntegerField(
        verbose_name="TSI MIX Pallets",
        null=True,
        blank=True,
        help_text="Number of TSI mixed pallets"
    )
    TSI_MIX_U = models.IntegerField(
        verbose_name="TSI MIX Units",
        null=True,
        blank=True,
        help_text="Number of TSI mixed units"
    )

    # FBA related fields
    SB = models.IntegerField(
        verbose_name="SB",
        null=True,
        blank=True,
        help_text="Number of SB units"
    )
    FBA = models.IntegerField(
        verbose_name="FBA Units",
        null=True,
        blank=True,
        help_text="Number of FBA units"
    )

    # User and time info
    start_time = models.DateTimeField(
        verbose_name="SBD/SLA (Processed)", # Zmieniono etykietę dla jasności
        help_text="This field stores the processed date/time.", # Zaktualizowano help_text
        null=True, # Pozwalamy na NULL, jeśli parsowanie się nie uda
        blank=True
    )

    sbd_sla_manual_input = models.CharField(
        verbose_name="Manual SBD/SLA Input",
        max_length=100,
        blank=True,
        null=True,
        help_text="Enter date and time manually (any format)."
    )

    # Additional info
    line = models.CharField(
        verbose_name="Line",
        max_length=100
    )
    comment = models.TextField(
        verbose_name="Comments",
        null=True,
        blank=True
    )
    delay = models.CharField(
        verbose_name="Delay Reason",
        max_length=200,
        null=True,
        blank=True
    )

    def save(self, *args, **kwargs):
        if self.line:
            self.line = self.line.upper()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ['start_time']
        verbose_name = "Stock"
        verbose_name_plural = "Stocks"

    def __str__(self):
        created_time_str = self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else "N/A"
        return f"Stock {self.ISA} - Created: {created_time_str}"


class DeletedStock(models.Model):
    original_stock_data = models.JSONField(
        verbose_name="Original Stock Data"
    )
    deleted_at = models.DateTimeField(
        verbose_name="Deleted At",
        auto_now_add=True
    )
    deleted_by = models.CharField(
        verbose_name="Deleted By",
        max_length=100,
        blank=True,
        null=True
    )

    class Meta:
        ordering = ['-deleted_at']
        verbose_name = "Deleted Stock"
        verbose_name_plural = "Deleted Stocks"

    def __str__(self):
        created_at_str = self.original_stock_data.get('created_at', 'N/A')
        created_time_display = "N/A"
        if created_at_str and created_at_str != 'N/A':
            try:
                 dt_obj = timezone.datetime.fromisoformat(created_at_str.replace('Z', '+00:00')) if created_at_str else None
                 if dt_obj:
                     created_time_display = timezone.localtime(dt_obj).strftime('%Y-%m-%d %H:%M')
            except (ValueError, TypeError):
                 created_time_display = created_at_str
        deleted_time_str = timezone.localtime(self.deleted_at).strftime('%Y-%m-%d %H:%M') if self.deleted_at else "N/A"
        return f"Deleted Stock {self.original_stock_data.get('ISA', 'N/A')} (Created: {created_time_display}) at {deleted_time_str}"


class RotomHistory(models.Model):
    trailer_id = models.CharField(max_length=50, db_index=True, verbose_name="Trailer ID")
    event_type = models.CharField(max_length=50, verbose_name="Event Type")
    event_timestamp = models.DateTimeField(default=timezone.now, verbose_name="Event Timestamp")
    user = models.CharField(max_length=100, blank=True, null=True, verbose_name="User")
    isa = models.IntegerField(null=True, blank=True, verbose_name="ISA Number")
    details = models.TextField(blank=True, null=True, verbose_name="Details")

    class Meta:
        ordering = ['-event_timestamp']
        verbose_name = "ROTOM History Event"
        verbose_name_plural = "ROTOM History Events"

    def __str__(self):
        timestamp_str = self.event_timestamp.strftime('%Y-%m-%d %H:%M')
        return f"{timestamp_str} - {self.trailer_id}: {self.event_type} by {self.user}"


class RotomState(models.Model):
    trailer_id = models.CharField(max_length=50, primary_key=True, verbose_name="Trailer ID")
    last_known_isa = models.IntegerField(null=True, blank=True, verbose_name="Last Known ISA")
    status = models.CharField(max_length=20, default='released', verbose_name="Status")
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"State for {self.trailer_id}: {self.status} (ISA: {self.last_known_isa})"


class RotomSummary(models.Model):
    id = models.PositiveIntegerField(primary_key=True, default=1, editable=False)
    reloaded_trailers = models.JSONField(default=list, verbose_name="Reloaded Trailers List")
    released_trailers = models.JSONField(default=list, verbose_name="Released Trailers List")
    last_reset = models.DateTimeField(default=timezone.now)
    # <<< ZMIANA: Dodano nową flagę inicjalizacji >>>
    is_initialized = models.BooleanField(default=False, verbose_name="Is Initialized")

    def save(self, *args, **kwargs):
        self.pk = 1
        super(RotomSummary, self).save(*args, **kwargs)

    def reset(self):
        self.reloaded_trailers = []
        self.released_trailers = []
        self.last_reset = timezone.now()
        # <<< ZMIANA: Resetowanie flagi inicjalizacji >>>
        self.is_initialized = False
        self.save()

    def __str__(self):
        return "Persistent ROTOM Summary Counters"

    class Meta:
        verbose_name_plural = "ROTOM Summary Counters"