# Generated by Django 5.0.5 on 2024-05-23 12:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Abonnement', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='abonnement',
            name='type_abonnement',
            field=models.CharField(default='premium', max_length=50),
        ),
    ]
