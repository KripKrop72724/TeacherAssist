from django.db import transaction
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model, password_validation

from auth.models import TwoFactor

User = get_user_model()


class SchemaTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

        schema = self.context["request"].tenant.schema_name

        refresh = self.get_token(self.user)
        refresh["schema"] = schema
        access = refresh.access_token
        access["schema"] = schema

        data["refresh"] = str(refresh)
        data["access"] = str(access)
        return data


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    otp      = serializers.CharField(write_only=True, required=False)

    def validate(self, attrs):
        jwt_ser = SchemaTokenObtainPairSerializer(
            data={
                "username": attrs["username"],
                "password": attrs["password"],
            },
            context={"request": self.context.get("request")},
        )
        try:
            jwt_ser.is_valid(raise_exception=True)
        except AuthenticationFailed:
            raise serializers.ValidationError({"non_field_errors": [_("Invalid credentials.")]})
        user   = jwt_ser.user
        access = jwt_ser.validated_data["access"]
        refresh= jwt_ser.validated_data["refresh"]

        tf = getattr(user, "two_factor", None)
        if tf and tf.enabled:
            otp = attrs.get("otp")
            if not otp:
                raise serializers.ValidationError({"otp":"Two-factor code required."})
            if not tf.get_totp().verify(otp, valid_window=1):
                raise serializers.ValidationError({"otp":"Invalid two-factor code."})

        return {
            "user":    user,
            "access":  access,
            "refresh": refresh
        }


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


class UserRegisterSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=150,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=_("Username already in use.")
            )
        ],
        help_text=_("Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."),
    )
    email = serializers.EmailField(
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=_("Email already registered.")
            )
        ],
        help_text=_("Required. Enter a valid email address."),
    )
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        help_text=_("Required. Must meet the password validation rules."),
        validators=[password_validation.validate_password],
    )
    password2 = serializers.CharField(
        write_only=True,
        label=_("Confirm password"),
        style={'input_type': 'password'},
        help_text=_("Enter the same password as before, for verification."),
    )

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {'password2': _("Passwords do not match.")}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2', None)
        raw_password = validated_data.pop('password')

        with transaction.atomic():
            user = User.objects.create_user(
                password=raw_password,
                **validated_data
            )
        return user

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model  = User
        fields = ("id", "username", "email", "first_name", "last_name")


class TwoFactorSetupSerializer(serializers.Serializer):
    secret           = serializers.CharField(read_only=True)
    provisioning_uri = serializers.CharField(read_only=True)


class TwoFactorEnableSerializer(serializers.Serializer):
    otp = serializers.CharField(write_only=True)


class TwoFactorDisableSerializer(serializers.Serializer):
    otp = serializers.CharField(write_only=True)


class JWKSerializer(serializers.Serializer):
    kty = serializers.CharField(help_text="Key Type (e.g. 'RSA').")
    use = serializers.CharField(help_text="How this key is used (e.g. 'sig' for signature).")
    alg = serializers.CharField(help_text="RSA algorithm (e.g. 'RS256').")
    kid = serializers.CharField(help_text="Key ID. Clients use this to select the correct key.")
    n = serializers.CharField(help_text="The RSA modulus, base64url-encoded.")
    e = serializers.CharField(help_text="The RSA public exponent, base64url-encoded.")


class JWKSResponseSerializer(serializers.Serializer):
    keys = serializers.ListField(child=JWKSerializer(),help_text="List of JSON Web Keys for JWT verification.")