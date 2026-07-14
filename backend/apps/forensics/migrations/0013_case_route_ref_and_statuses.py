import uuid

from django.db import migrations, models


def normalize_case_statuses(apps, _schema_editor):
    Case = apps.get_model("forensics", "Case")
    Case.objects.filter(closed_at__isnull=False).update(status="closed")
    Case.objects.filter(closed_at__isnull=True, status__in=["reviewing", "report-ready"]).update(status="open")


def populate_case_route_refs(apps, _schema_editor):
    Case = apps.get_model("forensics", "Case")
    for case in Case.objects.filter(route_ref__isnull=True).iterator():
        case.route_ref = uuid.uuid4()
        case.save(update_fields=["route_ref"])


class Migration(migrations.Migration):
    dependencies = [("forensics", "0012_evidenceuploadsession")]

    operations = [
        migrations.AddField(
            model_name="case",
            name="route_ref",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.RunPython(populate_case_route_refs, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="case",
            name="route_ref",
            field=models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.RunPython(normalize_case_statuses, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="case",
            name="status",
            field=models.CharField(choices=[("open", "Open"), ("closed", "Closed")], default="open", max_length=32),
        ),
    ]
