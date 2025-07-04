from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.


class User(AbstractUser):
    """
    Custom User model with Duo authentication status field
    """
    is_duo_authenticated = models.BooleanField(default=False)

    def __str__(self):
        return self.username