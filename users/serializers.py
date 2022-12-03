from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import User
from users.utils import send_email


class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=50, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate_username(self, username):
        if User.objects.filter(username=username).count() > 0:
            raise serializers.ValidationError("Username has already been taken")
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email).count() > 0:
            raise serializers.ValidationError("Email already exists")
        return email

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField(max_length=50, min_length=6, write_only=True)
    tokens = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'tokens']

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        user = authenticate(username=username, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials")

        # if not user.is_verified:
        #    raise AuthenticationFailed("Please verify your email your login")

        return {
            'username': user.username,
            'token': user.tokens
        }


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']

    def validate(self, attrs, **kwargs):
        email = attrs.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uibd64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            email_subject = "Password reset"
            email_body = f"Hi {user.username}, please use these data reset your password\nuidb64: {uibd64}\ntoken:{token}"
            send_email(to_user=user, subject=email_subject, body=email_body)
        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=50, min_length=6, write_only=True)
    uibd64 = serializers.CharField(max_length=100)
    token = serializers.CharField(max_length=100)

    class Meta:
        fields = ['new_password', 'uibd64', 'token']

    def validate(self, attrs):
        password = attrs.get('new_password', '')
        uibd64 = attrs.get('uibd64', '')
        token = attrs.get('token', '')
        try:
            user_id = smart_str(urlsafe_base64_decode(uibd64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise ValidationError

            user.set_password(password)
            user.save()
        except DjangoUnicodeDecodeError:
            return {
                'Token is invalid'
            }
        return attrs


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {
        'token_invalid': ('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh_token']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('token_invalid')
