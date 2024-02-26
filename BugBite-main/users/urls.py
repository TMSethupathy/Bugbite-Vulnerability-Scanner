from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.index,name='mainpage'),
    path('register',views.user_registration,name='register'),
    path('email_otp/',views.otp_verification,name="otp_verification"),
    path('login/',views.login,name='login'),

    path('logout/', views.logout_view, name='logout'),


    
]