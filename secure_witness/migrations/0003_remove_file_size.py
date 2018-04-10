# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secure_witness', '0002_auto_20141114_1946'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='file',
            name='size',
        ),
    ]
