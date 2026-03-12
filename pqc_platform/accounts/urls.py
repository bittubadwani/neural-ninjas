from django.urls import path
from .views import login_view, logout_view,verify_otp,home

urlpatterns = [
    path('', home, name='home'),
    path('login/', login_view, name='login'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('logout/', logout_view, name='logout'),

]
