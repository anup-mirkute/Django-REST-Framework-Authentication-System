from django.urls import path
from accounts.views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    #   accounts
    path('signup', RegistrationView.as_view(), name='signup'),
    path('verify-mail/<uidb64>/<token>/', verifyMail, name="verify-mail"),

    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),

    path('forget-password', ForgetPasswordRequestView.as_view(), name="forget-password-request"),
    path('forget-password/<uidb64>/<token>/', ForgetPasswordResetView.as_view(), name="forget-password-reset"),



] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)