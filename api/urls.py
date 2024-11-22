from django.urls import path
from accounts.views import *

urlpatterns = [

    #   accounts
    path('signup', RegistrationView.as_view(), name='signup'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),




]