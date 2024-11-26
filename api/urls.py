from django.urls import path
from accounts.views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    #   accounts
    path('signup', RegistrationView.as_view(), name='signup'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('verify-mail/<uidb64>/<token>/', verifyMail, name="verify-mail"),




] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)