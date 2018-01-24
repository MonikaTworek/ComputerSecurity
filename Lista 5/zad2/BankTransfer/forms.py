from django import forms

from BankTransfer.models import PendingTransfer


class TranferMetaForm(forms.ModelForm):
    def save(self, user, date, commit=True):
        # get the instance so we can add the user to it.
        instance = super(TranferMetaForm, self).save(commit=False)
        instance.user = user
        instance.date = date

        # Do we need to save all changes now?
        if commit:
            instance.save()
            self.save_m2m()

        return instance


class TransferForm(TranferMetaForm):
    class Meta:
        model = PendingTransfer
        fields = ['receiver', 'title', 'amount']


class SQLForm(forms.Form):
    query = forms.CharField(max_length=600)
