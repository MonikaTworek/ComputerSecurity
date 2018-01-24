from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse

from BankTransfer import models
from BankTransfer.forms import TransferForm
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
            Transfer.objects.create(receiver=t.receiver, title=t.title, amount=t.amount, user=t.user)
            t.delete()
        return redirect('history')
    return render(request, 'transfer_confirm.html', {'transfers': pending_transfers})


def create_history_view(request):
    transfers = [_ for _ in models.Transfer.objects.all() if _.user_id == request.user.id]
    return render(request, 'history.html', {'transfers': transfers})