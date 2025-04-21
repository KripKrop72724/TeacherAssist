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
    # no input body
    pass

class TenantCreateSerializer(serializers.Serializer):
    subdomain = serializers.RegexField(
        regex=r'^[a-zA-Z0-9]+$',
        max_length=50,
        help_text="Alphanumeric, max 50 chars"
    )

class TenantCreateResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    schema  = serializers.CharField()
    domain  = serializers.CharField()