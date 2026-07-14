from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("forensics", "0009_caseanalysissnapshot")]

    operations = [
        migrations.AlterField(
            model_name="userprofile",
            name="role",
            field=models.CharField(
                choices=[
                    ("Admin", "Admin"),
                    ("Investigator", "Investigator"),
                    ("Analyst", "Analyst"),
                    ("Viewer", "Viewer"),
                ],
                default="Viewer",
                max_length=32,
            ),
        ),
    ]
