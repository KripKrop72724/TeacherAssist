import pyotp
from django.conf import settings
from django.db import models


class TwoFactor(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor")
    secret = models.CharField(max_length=32, help_text="Base-32 secret for TOTP")
    enabled = models.BooleanField(default=False, help_text="2FA Activation Status")
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"2FA for {self.user}"

    def get_totp(self):
        return pyotp.TOTP(self.secret)

    def provisioning_uri(self):
        label = self.user.email or self.user.username
        issuer = settings.SITE_NAME
        return self.get_totp().provisioning_uri(name=label, issuer_name=issuer)
