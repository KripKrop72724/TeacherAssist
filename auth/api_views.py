import re
import pyotp
import requests
from django.conf import settings
from django.core.management import call_command
from django.db import transaction
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.serializers import (TokenObtainPairSerializer,TokenRefreshSerializer)
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse, OpenApiParameter
from auth.authentication import CookieJWTAuthentication
from auth.models import TwoFactor
from auth.serializers import LoginSerializer, RefreshSerializer, LogoutSerializer, TenantCreateSerializer, \
    TenantCreateResponseSerializer, CheckTenantSerializer, UserRegisterSerializer, UserDetailSerializer, \
    TwoFactorEnableSerializer, TwoFactorDisableSerializer, TwoFactorSetupSerializer
from auth.throttles import ConditionalScopeThrottle
from tenants.models import Tenant, Domain
from django.utils.translation import gettext_lazy as _

@extend_schema_view(
    login=extend_schema(
        summary="Login with optional 2FA",
        description=(
            "Authenticate a user and issue JWT access & refresh tokens as secure, HttpOnly cookies.\n\n"
            "**Behavior:**\n"
            "- **2FA disabled**: Validate username & password → 204 No Content + cookies.\n"
            "- **2FA enabled, no OTP**: 403 Forbidden + `{ otp_required: true }`.\n"
            "- **2FA enabled, invalid OTP**: 400 Bad Request + `{ otp: 'Invalid two-factor code.' }`.\n"
            "- **2FA enabled, valid OTP**: 204 No Content + cookies.\n\n"
            "**Cookies set:** `access_token` and `refresh_token`, flags: Secure, HttpOnly, SameSite=Lax."
        ),
        request=LoginSerializer,
        responses={
            204: OpenApiResponse(description="Logged in via cookies"),
            403: OpenApiResponse(description="OTP required: { otp_required: true }"),
            400: OpenApiResponse(description="Invalid credentials or OTP"),
        },
    ),
    refresh=extend_schema(
        summary="Refresh JWT access token",
        description=(
            "Rotate the access token by validating a refresh token (from cookie or body).  \n"
            "On success, sets a new `access_token` cookie and optionally returns a new `refresh`."
        ),
        request=RefreshSerializer,
        responses={
            200: OpenApiResponse(
                response=RefreshSerializer,
                description="Returns `{ access }` and updates access_token cookie."
            ),
            400: OpenApiResponse(description="No refresh token provided."),
            401: OpenApiResponse(description="Invalid refresh token."),
        },
    ),
    logout=extend_schema(
        summary="Logout user",
        description="Blacklist the refresh token (from cookie) and clear both access + refresh cookies.",
        request=LogoutSerializer,
        responses={200: OpenApiResponse(description="Logged out successfully.")},
    ),
    create_tenant=extend_schema(
        summary="Onboard a new tenant",
        description=(
            "Atomically create a new PostgreSQL schema and domain for a tenant.\n\n"
            "- **Request:** `{ subdomain, recaptcha_token }`  \n"
            "- **Checks:** alphanumeric‐only subdomain (1–50 chars), reserved names, reCAPTCHA v3 score ≥ 0.5, uniqueness.\n"
            "- **On success:** runs `migrate_schemas` for the new tenant schema."
        ),
        request=TenantCreateSerializer,
        responses={
            201: TenantCreateResponseSerializer,
            400: OpenApiResponse(description="Validation or reCAPTCHA failure"),
            409: OpenApiResponse(description="Subdomain already exists"),
            429: OpenApiResponse(description="Rate limit exceeded"),
            500: OpenApiResponse(description="Internal server error"),
        },
    ),
    check_tenant=extend_schema(
        summary="Check tenant subdomain availability",
        description=(
            "Quick lookup for whether a given subdomain is free to onboard.  \n"
            "Intended for front-end debounced checks before calling `create_tenant`."
        ),
        parameters=[
            OpenApiParameter(
                name="subdomain",
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description="Subdomain to check (alphanumeric, 1–50 chars)."
            )
        ],
        responses={
            200: CheckTenantSerializer,
            400: OpenApiResponse(description="Missing or invalid subdomain parameter."),
            429: OpenApiResponse(description="Rate limit exceeded."),
        },
    ),
    register=extend_schema(
        summary="Register a new user",
        description=(
            "Create a new user in the **current** tenant schema.  \n"
            "- **Request:** `{ username, email, password, password2 }`  \n"
            "- Performs uniqueness checks & password validation.  \n"
            "- Does **not** log in—the client must call `/auth/login/` afterwards."
        ),
        request=UserRegisterSerializer,
        responses={
            201: OpenApiResponse(response=UserDetailSerializer, description="User created"),
            400: OpenApiResponse(description="Validation error"),
            429: OpenApiResponse(description="Rate limit exceeded"),
        },
    ),
    two_factor_setup=extend_schema(
        summary="Initialize TOTP 2FA setup",
        description=(
            "Generate (or retrieve) the user's TOTP secret and provisioning URI.\n\n"
            "- **GET** returns `{ secret, provisioning_uri }` for scanning in Google Authenticator.\n"
            "- Idempotent: repeated calls reuse the same secret."
        ),
        responses={200: TwoFactorSetupSerializer},
    ),
    two_factor_enable=extend_schema(
        summary="Enable TOTP 2FA",
        description=(
            "Activate two-factor by verifying the first code from the user's authenticator app.\n\n"
            "- **Request:** `{ otp }`  \n"
            "- On success, flips `enabled=True` for the user."
        ),
        request=TwoFactorEnableSerializer,
        responses={200: OpenApiResponse(description="2FA enabled successfully")},
    ),
    two_factor_disable=extend_schema(
        summary="Disable TOTP 2FA",
        description=(
            "Turn off two-factor, after verifying a valid current code.\n\n"
            "- **Request:** `{ otp }`  \n"
            "- On success, flips `enabled=False`."
        ),
        request=TwoFactorDisableSerializer,
        responses={200: OpenApiResponse(description="2FA disabled successfully")},
    ),
)

class AuthViewSet(viewsets.GenericViewSet):
    """
    Handles **authentication**, **tenant management**, **user registration**, and **optional TOTP-based 2FA**.

    1. **Login** (`POST /auth/login/`)
       Authenticate credentials (and OTP if enabled) → issue JWT cookies.

    2. **Token Refresh** (`POST /auth/refresh/`)
       Rotate access token using refresh cookie or body → set new cookie.

    3. **Logout** (`POST /auth/logout/`)
       Blacklist the current refresh token → clear JWT cookies.

    4. **Tenant Onboarding** (`POST /auth/create_tenant/`)
       Create a new tenant schema & domain, protected by reCAPTCHA and rate limits.

    5. **Check Tenant** (`GET /auth/check_tenant/?subdomain=…`)
       Debounced availability check for front-end subdomain preflight.

    6. **User Registration** (`POST /auth/register/`)
       Create a new user within the tenant’s schema.

    7. **2FA Setup** (`GET /auth/two_factor_setup/`)
       Generate or retrieve a TOTP secret + provisioning URI.

    8. **2FA Enable** (`POST /auth/two_factor_enable/`)
       Verify first TOTP code to activate 2FA.

    9. **2FA Disable** (`POST /auth/two_factor_disable/`)
       Verify TOTP code to deactivate 2FA.
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes     = [AllowAny]
    throttle_classes       = [ConditionalScopeThrottle]

    @action(detail=False, methods=["post"], permission_classes=[AllowAny], authentication_classes=[])
    def login(self, request):
        inp = LoginSerializer(data=request.data)
        inp.is_valid(raise_exception=True)
        user = inp.validated_data["user"]
        access = inp.validated_data["access"]
        refresh = inp.validated_data["refresh"]

        resp = Response(status=status.HTTP_204_NO_CONTENT)
        for ck, lt in (
                ("AUTH_COOKIE", "ACCESS_TOKEN_LIFETIME"),
                ("REFRESH_COOKIE", "REFRESH_TOKEN_LIFETIME"),
        ):
            name = settings.SIMPLE_JWT[ck]
            lifetime = settings.SIMPLE_JWT[lt]
            token = inp.validated_data[ck == "AUTH_COOKIE" and "access" or "refresh"]

            resp.set_cookie(
                name, token,
                domain=settings.COOKIE_DOMAIN,
                path="/", max_age=int(lifetime.total_seconds()),
                secure=settings.SIMPLE_JWT[f"{ck}_SECURE"],
                httponly=settings.SIMPLE_JWT[f"{ck}_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT[f"{ck}_SAMESITE"],
            )
        return resp

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def two_factor_setup(self, request):
        user = request.user
        tf, created = TwoFactor.objects.get_or_create(
            user=user,
            defaults={"secret": pyotp.random_base32()}
        )
        data = {
            "secret":           tf.secret,
            "provisioning_uri": tf.provisioning_uri(),
        }
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def two_factor_enable(self, request):
        user = request.user
        serializer = TwoFactorEnableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tf = user.two_factor
        except TwoFactor.DoesNotExist:
            return Response({"error":"Call setup first."},
                            status=status.HTTP_400_BAD_REQUEST)

        otp = serializer.validated_data["otp"]
        if not tf.get_totp().verify(otp):
            return Response({"error":"Invalid code."},
                            status=status.HTTP_400_BAD_REQUEST)

        tf.enabled = True
        tf.save(update_fields=["enabled"])
        return Response({"detail":"2FA enabled."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def two_factor_disable(self, request):
        user = request.user
        serializer = TwoFactorDisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tf = user.two_factor
        except TwoFactor.DoesNotExist:
            return Response({"error":"2FA not active."},
                            status=status.HTTP_400_BAD_REQUEST)

        otp = serializer.validated_data["otp"]
        if not tf.get_totp().verify(otp):
            return Response({"error":"Invalid code."},
                            status=status.HTTP_400_BAD_REQUEST)

        tf.enabled = False
        tf.save(update_fields=["enabled"])
        return Response({"detail":"2FA disabled."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny], authentication_classes=[])
    def refresh(self, request):
        refresh_token = (
            request.data.get("refresh")
            or request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        )
        if not refresh_token:
            return Response({"error": _("No refresh token provided.")},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            return Response({"error": _("Invalid refresh token."), "details": str(e)},
                            status=status.HTTP_401_UNAUTHORIZED)

        access  = serializer.validated_data["access"]
        data    = {"access": access}
        new_ref = serializer.validated_data.get("refresh")
        if new_ref:
            data["refresh"] = new_ref

        resp = Response(data, status=status.HTTP_200_OK)
        resp.set_cookie(
            settings.SIMPLE_JWT["AUTH_COOKIE"],
            access,
            path="/",
            max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
        if new_ref:
            resp.set_cookie(
                settings.SIMPLE_JWT["REFRESH_COOKIE"],
                new_ref,
                path="/",
                max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
                secure=settings.SIMPLE_JWT["REFRESH_COOKIE_SECURE"],
                httponly=settings.SIMPLE_JWT["REFRESH_COOKIE_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT["REFRESH_COOKIE_SAMESITE"],
            )
        return resp

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def logout(self, request):
        token = request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        if not token:
            return Response({"error": _("No refresh token in cookies.")},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            RefreshToken(token).blacklist()
        except TokenError as e:
            return Response({"error": _("Failed to blacklist token."), _("details"): _(str(e))},
                            status=status.HTTP_400_BAD_REQUEST)

        resp = Response({"detail": _("Logged out.")}, status=status.HTTP_200_OK)
        resp.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"], path="/")
        resp.delete_cookie(settings.SIMPLE_JWT["REFRESH_COOKIE"], path="/")
        return resp

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], authentication_classes=[])
    def check_tenant(self, request):
        sub = request.query_params.get("subdomain", "").strip().lower()
        reserved = {n.lower() for n in settings.RESERVED_SUBDOMAINS}

        if not sub:
            return Response(
                {"available": False,
                 "reason": _("Subdomain parameter is required.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        if sub in reserved:
            return Response({"available": False, "reason": _("Reserved name.")},
                            status=status.HTTP_200_OK)
        if not re.fullmatch(r"[A-Za-z0-9]{1,50}", sub):
            return Response(
                {"available": False,
                 "reason": _("1–50 alphanumeric characters only.")},
                status=status.HTTP_200_OK
            )
        if Tenant.objects.filter(schema_name=sub).exists() or Domain.objects.filter(domain__startswith=f"{sub}.").exists():
            return Response({"available": False, "reason": _("Already in use.")},
                            status=status.HTTP_200_OK)

        return Response({"available": True}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny], authentication_classes=[])
    def create_tenant(self, request):
        raw = request.data.get("subdomain", "")
        sub = str(raw).strip().lower()
        reserved = {name.lower() for name in settings.RESERVED_SUBDOMAINS}

        if not sub:
            return Response(
                {"error": _("Subdomain is required.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        if sub in reserved:
            return Response(
                {"error": _("That name is reserved.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not re.fullmatch(r"^[A-Za-z0-9]{1,50}$", sub):
            return Response(
                {"error": _("Subdomain must be 1–50 alphanumeric characters.")},
                status=status.HTTP_400_BAD_REQUEST
            )

        if settings.TENANT_CREATION_REQUIRE_CAPTCHA:
            recaptcha_token = request.data.get("recaptcha_token")
            if not recaptcha_token:
                return Response(
                    {"error": _("`recaptcha_token` is required.")},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                rec_r = requests.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={
                        "secret":   settings.RECAPTCHA_SECRET_KEY,
                        "response": recaptcha_token,
                    },
                    timeout=5,
                )
                rec_r.raise_for_status()
                rec = rec_r.json()
            except requests.RequestException as e:
                return Response(
                    {
                        "error":   _("Recaptcha service unavailable."),
                        "details": str(e),
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            if not rec.get("success") or rec.get("score", 0) < 0.5:
                return Response(
                    {"error": _("Recaptcha validation failed.")},
                    status=status.HTTP_400_BAD_REQUEST
                )

        domain = f"{sub}.{settings.TENANT_SUBDOMAIN_BASE}"
        if Tenant.objects.filter(schema_name=sub).exists() or Domain.objects.filter(domain=domain).exists():
            return Response(
                {"error": _("Tenant or domain already exists.")},
                status=status.HTTP_409_CONFLICT
            )

        try:
            with transaction.atomic():
                tenant = Tenant(schema_name=sub, name=sub.capitalize())
                tenant.save()  # auto_create_schema=True creates the schema
                Domain.objects.create(
                    tenant=tenant,
                    domain=domain,
                    is_primary=True
                )
        except Exception as e:
            return Response(
                {
                    "error":   _("Failed to create tenant record."),
                    "details": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try:
            call_command(
                "migrate_schemas",
                schema_name=sub,
                interactive=False,
                verbosity=1,
            )
        except Exception as e:
            try:
                tenant.delete()
            except Exception:
                pass
            return Response(
                {
                    "error":   _("Tenant onboarding failed during migrations."),
                    "details": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {
                "message": _("Tenant created successfully."),
                "schema":  sub,
                "domain":  domain
            },
            status=status.HTTP_201_CREATED
        )

    @action(detail=False, methods=["post"], permission_classes=[AllowAny], authentication_classes=[])
    def register(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        out = UserDetailSerializer(user)
        return Response(out.data, status=status.HTTP_201_CREATED)
