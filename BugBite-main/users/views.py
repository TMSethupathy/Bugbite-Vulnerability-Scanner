from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegistrationForm, OTPVerificationForm,LoginForm
from .models import User, OTP
import random
import string
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login,logout


def index(request):
    return render(request,'index.html')


def set_password(user, password):
    user.password = make_password(password)
    user.save()

def user_registration(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            #user.set_password(user.password)
            user.save()
            
            # Generate OTP and send email
            otp = ''.join(random.choices(string.digits, k=6))
            OTP.objects.create(user=user, otp=otp)
            send_mail(
                'OTP for JUNO Web Vulnerability Scanner',
                'Your OTP is: ' + otp,
                'srkumar87787@gmail.com',
                [user.email],
                fail_silently=False,
            )
            return redirect('otp_verification')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration.html', {'form': form})

def otp_verification(request):
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            try:
                user_otp = OTP.objects.get(otp=otp)
                user = user_otp.user
                user.is_active = True
                user.save()
                messages.success(request, 'Your account has been verified successfully.')
                return redirect('login')
            except OTP.DoesNotExist:
                messages.error(request, 'Invalid OTP.')
    else:
        form = OTPVerificationForm()
    return render(request, 'otp_verification.html', {'form': form})


def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            user = User.objects.get(username=request.POST['username'],password=request.POST['password'])
            if user:
                return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')