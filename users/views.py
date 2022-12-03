import jwt
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import User
from users.serializers import RegisterUserSerializer, LoginSerializer, LogoutSerializer, ResetPasswordRequestSerializer, SetNewPasswordSerializer
from users.utils import send_email


class RegisterUserView(generics.GenericAPIView):
    serializer_class = RegisterUserSerializer

    def post(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.create(serializer.validated_data)

        current_site = get_current_site(request=request).domain
        token = RefreshToken.for_user(instance).access_token
        verification_link = "http://" + current_site + reverse('users:verify-user') + "?token=" + str(token)
        email_subject = "Email verification"
        email_body = f"Hi {instance.username}, please click on below link to verify your email\n{verification_link}"
        send_email(to_user=instance, subject=email_subject, body=email_body)
        return Response(self.serializer_class(instance).data, status=status.HTTP_201_CREATED)


class VerifyEmailView(generics.GenericAPIView):

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({
                'message': 'Successfully verified the email',
                'status': status.HTTP_200_OK
            })
        except jwt.ExpiredSignatureError:
            return Response({
                'message': 'Token has expired',
                'status': status.HTTP_400_BAD_REQUEST
            })
        except jwt.exceptions.DecodeError:
            return Response({
                'message': 'Invalid token',
                'status': status.HTTP_400_BAD_REQUEST
            })


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class ResetPasswordRequestView(generics.GenericAPIView):
    serializer_class = ResetPasswordRequestSerializer

    def post(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({
            'message': 'Password reset email sent',
            'status': status.HTTP_200_OK
        })


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({
            'message': 'Password is successfully reset'
        })


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = permissions.IsAuthenticated,

    def post(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
