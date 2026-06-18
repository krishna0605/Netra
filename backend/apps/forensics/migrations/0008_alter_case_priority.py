from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0007_case_workspace_metadata"),
    ]

    operations = [
        migrations.AlterField(
            model_name="case",
            name="priority",
            field=models.CharField(
                choices=[
                    ("", "Unset"),
                    ("Standard", "Standard"),
                    ("Urgent", "Urgent"),
                    ("Critical", "Critical"),
                ],
                default="Standard",
                max_length=32,
            ),
        ),
    ]
