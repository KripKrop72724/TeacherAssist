from rest_framework import serializers
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)

class LoginSerializer(TokenObtainPairSerializer):
    # inherits `username` & `password` in → `access` & `refresh` out
    pass

class RefreshSerializer(TokenRefreshSerializer):
    # inherits `refresh` in → `access` out
    pass

class LogoutSerializer(serializers.Serializer):
    pass

class TenantCreateSerializer(serializers.Serializer):
    subdomain        = serializers.RegexField(
        regex=r'^[A-Za-z0-9]{1,50}$',
        max_length=50,
        help_text="1–50 alphanumeric characters",
    )
    recaptcha_token  = serializers.CharField(
        help_text="Google reCAPTCHA v3 token from client"
    )

class TenantCreateResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    schema  = serializers.CharField()
    domain  = serializers.CharField()


class CheckTenantSerializer(serializers.Serializer):
    available = serializers.BooleanField()
    reason    = serializers.CharField(required=False, allow_blank=True)