from django.contrib import admin

from apps.forensics import models


@admin.register(models.Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "investigator", "status", "priority", "report_status", "created_at")
    search_fields = ("id", "title", "investigator")


@admin.register(models.EvidenceFile)
class EvidenceFileAdmin(admin.ModelAdmin):
    list_display = ("id", "case", "filename", "evidence_type", "sha256", "status", "created_at")
    search_fields = ("id", "filename", "sha256")


admin.site.register(models.CaptureJob)
admin.site.register(models.Sensor)
admin.site.register(models.CaptureChunk)
admin.site.register(models.OperationalEvent)
admin.site.register(models.WorkerHeartbeat)
admin.site.register(models.WorkerStageReceipt)
admin.site.register(models.ProcessingJob)
admin.site.register(models.SessionSummary)
admin.site.register(models.Alert)
admin.site.register(models.DetectionMatch)
admin.site.register(models.AnomalyRecord)
admin.site.register(models.Report)
admin.site.register(models.Export)
admin.site.register(models.IntegrationConnection)
admin.site.register(models.CaseHistoryEvent)
admin.site.register(models.AccessLog)
admin.site.register(models.ComplianceControl)
