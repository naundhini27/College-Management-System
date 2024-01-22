# Generated by Django 2.2.3 on 2020-07-30 04:46

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="semester",
            name="semester",
            field=models.CharField(
                blank=True,
                choices=[("Odd", "Odd"), ("Even", "Even")],
                max_length=10,
                unique=True,
            ),
        ),
    ]
