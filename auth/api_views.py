import re
from rest_framework.throttling import ScopedRateThrottle
import requests
import auth.openapi
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
from auth.serializers import LoginSerializer, RefreshSerializer, LogoutSerializer, TenantCreateSerializer, \
    TenantCreateResponseSerializer, CheckTenantSerializer, UserRegisterSerializer, UserDetailSerializer
from auth.throttles import ConditionalScopeThrottle
from tenants.models import Tenant, Domain
from django.utils.translation import gettext_lazy as _

@extend_schema_view(
    login=extend_schema(
        summary="Obtain JWT tokens",
        description="Given valid credentials, returns access+refresh tokens and sets them as secure, HTTP-only cookies.",
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                response=LoginSerializer,
                description="Returns `{ access, refresh }` and sets cookies."
            )
        },
    ),
    refresh=extend_schema(
        summary="Refresh access token",
        description="Refresh the access token, reading the refresh token from cookie or body.",
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
        summary="Logout & blacklist refresh token",
        description="Blacklists the refresh token (from cookie) and clears both cookies.",
        request=LogoutSerializer,
        responses={200: OpenApiResponse(description="Logged out successfully.")},
    ),
    create_tenant=extend_schema(
        summary="Onboard a new tenant",
        description=(
            "Creates a new schema and domain. "
            "Requires `subdomain` and a `recaptcha_token` from Google reCAPTCHA v3."
        ),
        request=TenantCreateSerializer,
        responses={
            201: TenantCreateResponseSerializer,
            400: OpenApiResponse(description="Validation or reCAPTCHA failure"),
            409: OpenApiResponse(description="Subdomain already exists"),
            429: OpenApiResponse(description="Rate limit exceeded"),
            500: OpenApiResponse(description="Internal error"),
        },
    ),
    check_tenant=extend_schema(
        summary="Check tenant availability",
        description=(
                "Returns whether a subdomain is available. "
                "Intended for front-end debounced checks."
        ),
        parameters=[
            OpenApiParameter(
                name="subdomain",
                type=str,
                location="query",
                required=True,
                description="Proposed tenant subdomain to check."
            )
        ],
        responses={
            200: CheckTenantSerializer,
            400: OpenApiResponse(description="Missing or invalid subdomain parameter."),
            429: OpenApiResponse(description="Rate limit exceeded."),
        },
    ),
    register=extend_schema(
        summary="Register a new user/login",
        description="Creates a new user in the current tenant schema.",
        request=UserRegisterSerializer,
        responses={
            201: OpenApiResponse(response=UserDetailSerializer, description="User created"),
            400: OpenApiResponse(description="Validation error"),
            429: OpenApiResponse(description="Rate limit exceeded"),
        },
    )
)

class AuthViewSet(viewsets.GenericViewSet):
    """
    - POST /auth/login/         → issue JWTs as cookies
    - POST /auth/refresh/       → rotate access_token cookie
    - POST /auth/logout/        → blacklist + clear cookies
    - POST /auth/create_tenant/ → onboard a new tenant (atomic)
    - POST /auth/register/      → register a login user for any tenant
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes     = [AllowAny]
    throttle_classes       = [ConditionalScopeThrottle]

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def login(self, request):
        serializer = TokenObtainPairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        access, refresh = (
            serializer.validated_data["access"],
            serializer.validated_data["refresh"],
        )

        resp = Response({_("access"): access, _("refresh"): refresh},
                        status=status.HTTP_200_OK)
        # set cookies site-wide
        for name, token, lifetime in (
            (settings.SIMPLE_JWT["AUTH_COOKIE"], access,
             settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]),
            (settings.SIMPLE_JWT["REFRESH_COOKIE"], refresh,
             settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]),
        ):
            resp.set_cookie(
                name,
                token,
                path="/",
                max_age=int(lifetime.total_seconds()),
                secure=settings.SIMPLE_JWT[f"{name.upper()}_SECURE"],
                httponly=settings.SIMPLE_JWT[f"{name.upper()}_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT[f"{name.upper()}_SAMESITE"],
            )
        return resp

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def refresh(self, request):
        refresh_token = (
            request.data.get("refresh")
            or request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        )
        if not refresh_token:
            return Response({_("error"): _("No refresh token provided.")},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            return Response({_("error"): _("Invalid refresh token."), _("details"): str(e)},
                            status=status.HTTP_401_UNAUTHORIZED)

        access  = serializer.validated_data["access"]
        data    = {_("access"): access}
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
            return Response({_("error"): _("No refresh token in cookies.")},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            RefreshToken(token).blacklist()
        except TokenError as e:
            return Response({_("error"): _("Failed to blacklist token."), _("details"): _(str(e))},
                            status=status.HTTP_400_BAD_REQUEST)

        resp = Response({_("detail"): _("Logged out.")}, status=status.HTTP_200_OK)
        resp.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"], path="/")
        resp.delete_cookie(settings.SIMPLE_JWT["REFRESH_COOKIE"], path="/")
        return resp

    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def check_tenant(self, request):
        sub = request.query_params.get("subdomain", "").strip().lower()
        reserved = {n.lower() for n in settings.RESERVED_SUBDOMAINS}

        if not sub:
            return Response(
                {_("available"): False,
                 _("reason"): _("Subdomain parameter is required.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        if sub in reserved:
            return Response({_("available"): False, _("reason"): _("Reserved name.")},
                            status=status.HTTP_200_OK)
        if not re.fullmatch(r"[A-Za-z0-9]{1,50}", sub):
            return Response(
                {_("available"): False,
                 _("reason"): _("1–50 alphanumeric characters only.")},
                status=status.HTTP_200_OK
            )
        if Tenant.objects.filter(schema_name=sub).exists() or Domain.objects.filter(domain__startswith=f"{sub}.").exists():
            return Response({_("available"): False, _("reason"): _("Already in use.")},
                            status=status.HTTP_200_OK)

        return Response({_("available"): True}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def create_tenant(self, request):
        sub = (request.data.get("subdomain") or "").strip().lower()
        reserved = {n.lower() for n in settings.RESERVED_SUBDOMAINS}

        if not sub:
            return Response({_("error"): _("Subdomain is required.")},
                            status=status.HTTP_400_BAD_REQUEST)
        if sub in reserved:
            return Response({_("error"): _("Reserved name.")},
                            status=status.HTTP_400_BAD_REQUEST)
        if not re.fullmatch(r"[A-Za-z0-9]{1,50}", sub):
            return Response({_("error"): _("1–50 alphanumeric chars only.")},
                            status=status.HTTP_400_BAD_REQUEST)

        if settings.TENANT_CREATION_REQUIRE_CAPTCHA:
            recaptcha = request.data.get("recaptcha_token")
            if not recaptcha:
                return Response({_("error"): _("recaptcha_token is required.")}, status=400)
            try:
                rec_r = requests.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={
                        "secret":   settings.RECAPTCHA_SECRET_KEY,
                        "response": recaptcha,
                    },
                    timeout=5,
                ).json()
            except requests.RequestException as e:
                return Response(
                    {_("error"):_("Recaptcha service unavailable."),_("details"):_(str(e))},
                    status=503
                )
            if not rec_r.get("success") or rec_r.get("score", 0) < 0.5:
                return Response({_("error"):_("Recaptcha validation failed.")}, status=400)

        domain = f"{sub}.{settings.TENANT_SUBDOMAIN_BASE}"
        if Tenant.objects.filter(schema_name=sub).exists() or Domain.objects.filter(domain=domain).exists():
            return Response({_("error"): _("Already exists.")},
                            status=status.HTTP_409_CONFLICT)

        try:
            with transaction.atomic():
                tenant = Tenant(schema_name=sub, name=sub.capitalize())
                tenant.save()
                Domain.objects.create(
                    tenant=tenant, domain=domain, is_primary=True
                )
        except Exception as e:
            return Response({_("error"): _("Failed to create records."),
                             _("details"): _(str(e))},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            call_command(
                "migrate_schemas",
                schema_name=sub,
                interactive=False,
                verbosity=1,
            )
        except Exception as e:
            tenant.delete()
            return Response({_("error"): _("Migration failed."),
                             _("details"): _(str(e))},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            _("message"): _("Tenant created."),
            "schema":  sub,
            "domain":  domain
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def register(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        out = UserDetailSerializer(user)
        return Response(out.data, status=status.HTTP_201_CREATED)
