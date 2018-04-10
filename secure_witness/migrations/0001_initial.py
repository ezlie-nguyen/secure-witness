# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Bulletin',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=128)),
                ('date_created', models.DateField()),
                ('date_modified', models.DateField()),
                ('location', models.CharField(max_length=128)),
                ('description', models.CharField(max_length=1024)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('content', models.FileField(upload_to=b'')),
                ('encryption_params', models.CharField(max_length=128)),
                ('date_created', models.DateField()),
                ('date_modified', models.DateField()),
                ('bulletin', models.ForeignKey(to='secure_witness.Bulletin')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Folder',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=128)),
                ('date_created', models.DateField()),
                ('date_modified', models.DateField()),
                ('location', models.CharField(max_length=128)),
                ('description', models.CharField(max_length=1024)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='bulletin',
            name='folder',
            field=models.ForeignKey(to='secure_witness.Folder'),
            preserve_default=True,
        ),
    ]
