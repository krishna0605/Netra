from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0003_phase3_security_ops"),
    ]

    operations = [
        migrations.AlterField(
            model_name="integrationconnection",
            name="status",
            field=models.CharField(default="pending", max_length=32),
        ),
    ]
