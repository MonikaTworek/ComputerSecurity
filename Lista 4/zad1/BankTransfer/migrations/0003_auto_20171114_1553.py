# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-14 14:53
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('BankTransfer', '0002_transfermodel_user'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='TransferModel',
            new_name='PendingTransferModel',
        ),
    ]