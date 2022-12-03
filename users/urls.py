from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from users import views


urlpatterns = [
    path('register/', views.RegisterUserView.as_view(), name='register-user'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-user'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('password-reset-request/', views.ResetPasswordRequestView.as_view(), name='password-reset-request'),
    path('password-reset-confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm')
]
