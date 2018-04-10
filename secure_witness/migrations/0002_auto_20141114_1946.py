# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('secure_witness', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='author',
            field=models.ForeignKey(default=0, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='file',
            name='check',
            field=models.CharField(default=0, max_length=24),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='file',
            name='name',
            field=models.CharField(default='', max_length=128),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='file',
            name='rand',
            field=models.CharField(default='', max_length=24),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='file',
            name='size',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='bulletin',
            name='folder',
            field=models.ForeignKey(to='secure_witness.Folder', null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='file',
            name='bulletin',
            field=models.ForeignKey(to='secure_witness.Bulletin', null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='file',
            name='content',
            field=models.FileField(upload_to=b'files'),
            preserve_default=True,
        ),
    ]
