from django.db import migrations, models


DETERMINISTIC_DETECTOR_VERSION = "detector-registry-v1"
LEGACY_MISLABELLED_VERSION = "scikit-v1"


def correct_detector_provenance(apps, _schema_editor):
    AnomalyRecord = apps.get_model("forensics", "AnomalyRecord")
    AnomalyRecord.objects.filter(model_version=LEGACY_MISLABELLED_VERSION).update(
        model_version=DETERMINISTIC_DETECTOR_VERSION
    )


def restore_legacy_label(apps, _schema_editor):
    AnomalyRecord = apps.get_model("forensics", "AnomalyRecord")
    AnomalyRecord.objects.filter(model_version=DETERMINISTIC_DETECTOR_VERSION).update(
        model_version=LEGACY_MISLABELLED_VERSION
    )


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0016_analysis_references_and_integration_links"),
    ]

    operations = [
        migrations.AlterField(
            model_name="anomalyrecord",
            name="model_version",
            field=models.CharField(default=DETERMINISTIC_DETECTOR_VERSION, max_length=80),
        ),
        migrations.RunPython(correct_detector_provenance, restore_legacy_label),
    ]
