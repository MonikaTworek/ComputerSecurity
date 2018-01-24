from django.contrib.auth.decorators import user_passes_test
from django.db import connection
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from BankTransfer import models
from BankTransfer.forms import TransferForm, SQLForm
from BankTransfer.models import Transfer
from django.utils import timezone


def create_transfer_view(request):
    if request.method == 'POST':
        form = TransferForm(request.POST)
        if form.is_valid():
            form.save(user=request.user, date=timezone.now())
            return redirect('transfer_confirm')
    else:
        form = TransferForm()
    return render(request, 'transfer.html', {'form': form})


def create_transfer_confirm_view(request):
    pending_transfers = [_ for _ in models.PendingTransfer.objects.all() if _.user_id == request.user.id]
    if request.method == 'POST':
        for t in pending_transfers:
            Transfer.objects.create(receiver=t.receiver, title=t.title, amount=t.amount, user=t.user, date=t.date)
            t.delete()
        return redirect('transfer')
    return render(request, 'transfer_confirm.html', {'transfers': pending_transfers})


@csrf_exempt
@user_passes_test(lambda u: u.is_superuser)
def create_transfer_confirm_admin_view(request):
    pending_transfers = [_ for _ in models.PendingTransfer.objects.all()]
    if request.method == 'POST':
        for t in pending_transfers:
            Transfer.objects.create(receiver=t.receiver, title=t.title, amount=t.amount, user=t.user, date=t.date)
            t.delete()
        return redirect('home')
    return render(request, 'transfer_confirm.html', {'transfers': pending_transfers})


def create_transfer_history_view(request):
    transfers = [_ for _ in models.Transfer.objects.all() if _.user_id == request.user.id]
    return render(request, 'history.html', {'transfers': transfers})


def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]


def create_sql_inject_view(request):
    form = SQLForm()
    if request.method == 'POST':
        form = SQLForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            query = cd.get('query')

            with connection.cursor() as cursor:
                cursor.execute(query)
                return render(request, 'sql_inject.html', {'form': form, 'result': cursor.fetchall()})

    return render(request, 'sql_inject.html', {'form': form, 'result': {}})
