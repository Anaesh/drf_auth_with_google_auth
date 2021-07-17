from social_auth import serializers
from .renderer import UserRenderer
from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.response import Response
from .serializers import EmailVerificationSerializer, LoginSerializer, LogoutSerializer, RegisterSerializer, ResetPasswordRequestSerializer, SetNewPasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from rest_framework import permissions
from rest_framework_simplejwt.authentication import JWTAuthentication

# Create your views here.

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email_verify')
        absurl = "http://"+current_site+relative_link+"?token="+str(token)
        email_body = 'Hi '+ user.username + '\n Use link below to verify your email \n'+absurl
        data = {'body': email_body, 'subject':'Verify Your Email', 'to': user.email}
        Util.send_mail(data)

        return Response(user_data, status=status.HTTP_201_CREATED)

class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer
    renderer_classes = (UserRenderer,)

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Give a auth token', type=openapi.TYPE_STRING)
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email':'Successfully Verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error':'Activation Link Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error':'Invalid Token - '+str(identifier)}, status=status.HTTP_400_BAD_REQUEST)
        
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordRequestSerializer
    def post(self, request):
        data = {'request': request, 'data': request.data}
        serializer = self.serializer_class(data=data)

        email = request.data['email']
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relative_link = reverse('password_reset', kwargs={'uidb64': uidb64, 'token': token})
            absurl = "http://"+current_site+relative_link
            email_body = 'Hello '+ user.username + '\n Use link below to reset your password \n'+absurl
            data = {'body': email_body, 'subject':'Reset Your Password', 'to': user.email}
            Util.send_mail(data)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'You do not have the account for this email id'}, status=status.HTTP_401_UNAUTHORIZED)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credentials valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
            
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    renderer_classes = (UserRenderer,)
    
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class UserDetailView(generics.GenericAPIView):

    permission_classes = [permissions.IsAuthenticated,]
    
    def get(self, request):
        try:
            
            user = User.objects.get(email=request.user)
            status_code = status.HTTP_200_OK
            response = {
                'success': 'true',
                'status code': status_code,
                'message': 'User detail fetched successfully',
                'data': [{
                    'username': user.username,
                    'email': user.email,
                    'is_verified': user.is_verified,
                    'is_active': user.is_active,
                    'is_staff': user.is_staff,
                    'auth_provider': user.auth_provider,
                    'created_at': user.created_at,
                    'updated_at': user.updated_at,
                    }]
                }

        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
                }
        return Response(response, status=status_code)    

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer 
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request):
        serializer= self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
