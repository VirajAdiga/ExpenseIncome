from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

from users.managers import UserManager


class User(AbstractUser):
    is_verified = models.BooleanField(default=False)

    objects = UserManager()

    def __str__(self):
        return self.username

    @property
    def tokens(self):
        refresh_token = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh_token),
            'access': str(refresh_token.access_token)
        }
