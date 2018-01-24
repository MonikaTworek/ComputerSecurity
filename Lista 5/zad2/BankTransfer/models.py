from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.db import models


# Create your models here.

class PendingTransfer(models.Model):
    account_regex = RegexValidator(regex=r'^\d{26}$', message="Bank account must have 26 digits.")

    receiver = models.CharField(validators=[account_regex], null=False, max_length=26)
    title = models.CharField(max_length=600, blank=False, null=False)
    amount = models.FloatField()
    user = models.ForeignKey(User, editable=False)
    date = models.DateTimeField(null=True)


class Transfer(models.Model):
    receiver = models.CharField(null=False, max_length=26)
    title = models.CharField(max_length=600, blank=False, null=False)
    amount = models.FloatField()
    user = models.ForeignKey(User, editable=False)
    date = models.DateTimeField(null=True)
