# Generated by Django 2.0 on 2024-04-19 12:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dock_nyr', '0003_alter_stock_ac'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stock',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
