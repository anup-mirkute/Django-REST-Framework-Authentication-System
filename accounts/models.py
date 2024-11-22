import datetime
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator, MaxLengthValidator
from helper.CustomValidator import *
from helper.constants import *


class User(AbstractUser):
    first_name = None
    last_name = None
    user_id = models.CharField(max_length=14, unique=True, editable=False)
    name = models.CharField(max_length=50, blank=True, null=True, validators=[MaxLengthValidator(50)], verbose_name=_("Full Name"), help_text=_("Enter the full name."))
    email = models.EmailField(max_length=255, unique=True, verbose_name=_("Email Address"), help_text=_("Enter the email address."))
    is_email_verified = models.BooleanField(default=False, verbose_name=_("Email Verified"), help_text=_("Indicates if the user's email address is verified."))
    phone_number = models.CharField(
        max_length=15, unique=True, blank=True, null=True,
        validators=[RegexValidator(r"^\+?1?\d{9,15}$", message=_("Enter a valid phone number."))],
        verbose_name=_("Phone Number"), help_text=_("Phone number with country code.")
    )
    is_phone_no_verified = models.BooleanField(default=False, verbose_name=_("Phone Verified"), help_text=_("Indicates if the user's phone number is verified."))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated At"))
    account_type = models.IntegerField(choices=ACCOUNT_TYPE, default=0)

    def __str__(self):
        return self.user_id
    
    def generate_unique_id(self):
        current_dtts = datetime.datetime.now()
        generated_id = f"AS{current_dtts.strftime("%d%m%y%H%M%S")}"
        return generated_id
    
    def clean(self):
        for field in self._meta.fields:
            value = getattr(self, field.name)
            if isinstance(value, str):
                setattr(self, field.name, value.strip())
        super().clean()

    def save(self, *args, **kwargs):
        if not self.user_id:
            self.user_id = self.generate_unique_id()

        self.full_clean()
        super().save(*args, **kwargs)

    
    class Meta:
        db_table = 'accounts"."users'
        indexes = [
            models.Index(fields=['user_id', 'username', 'email']),
        ]

        verbose_name = _("User")
        verbose_name_plural = _("Users")
        ordering = ["-date_joined"]