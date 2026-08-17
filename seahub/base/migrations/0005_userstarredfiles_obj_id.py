# -*- coding: utf-8 -*-
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0004_filetrash'),
    ]

    operations = [
        migrations.AddField(
            model_name='userstarredfiles',
            name='obj_id',
            field=models.CharField(db_index=True, max_length=64, null=True),
        ),
    ]
