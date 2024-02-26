from django import forms
from .models import Scan

class ScanForm(forms.ModelForm):
    class Meta:
        model = Scan
        fields = ['projectname', 'url', 'description']
        widgets = {
            'projectname': forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter Project name','autocomplete':'off'}),
            'url': forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter url','autocomplete':'off'}),
            'description': forms.Textarea(attrs={'rows':4,'class':'form-control my-2','placeholder':'Enter description','autocomplete':'off'})
        }
