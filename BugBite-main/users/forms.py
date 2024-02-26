from django import forms
from .models import User

class UserRegistrationForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter Username','autocomplete':'off'}))
    fullname = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter Your Fullname','autocomplete':'off'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control my-2','placeholder':'Enter Email Address','autocomplete':'off'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my-2','placeholder':'Enter Password','autocomplete':'off'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my-2','placeholder':'Enter confirm Password','autocomplete':'off'}))
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(max_length=6 ,widget=forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter the OTP','autocomplete':'off'}))


class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control my-2','placeholder':'Enter the username','autocomplete':'off'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my-2','placeholder':'Enter the Password','autocomplete':'off'}))




