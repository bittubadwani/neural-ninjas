from django.db import models
from django.contrib.auth.models import User

class UserOTP(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)

    otp_secret = models.CharField(max_length=32)

    otp_enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username
