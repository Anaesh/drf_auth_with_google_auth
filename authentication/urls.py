from os import name
from django.urls import path
from .views import LoginAPIView, LogoutAPIView, PasswordTokenCheckAPI, RegisterView, RequestPasswordResetEmail, SetNewPasswordAPIView, UserDetailView, VerifyEmail
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('email-verify/', VerifyEmail.as_view(), name='email_verify'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-password/', RequestPasswordResetEmail.as_view(), name='request_reset_password'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password_reset'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password_reset_complete'),
    path('profile/', UserDetailView.as_view(), name='profile'),
]