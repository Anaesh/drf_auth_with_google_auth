from os import access
from django.db import models

# Create your models here.
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.db.models.expressions import F
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError("User should have a username")
        if email is None:
            raise TypeError("User should have a email")
        
        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)

        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError("Password should not be empty")
        
        user =  self.create_user(username,email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

AUTH_PROVIDERS = {'google':'google', 'email':'email'}

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    auth_provider = models.CharField(max_length=255, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh_token = RefreshToken.for_user(self)
        return {
            'refresh':str(refresh_token) ,
            'access':str(refresh_token.access_token),
        }
    

