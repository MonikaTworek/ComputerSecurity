# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-14 15:00
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('BankTransfer', '0004_auto_20171114_1558'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='TransferModel',
            new_name='PendingTransferModel',
        ),
    ]
