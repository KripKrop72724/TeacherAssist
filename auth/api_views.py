import re
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
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

from auth.authentication import CookieJWTAuthentication
from auth.serializers import LoginSerializer, RefreshSerializer, LogoutSerializer, TenantCreateSerializer, \
    TenantCreateResponseSerializer
from tenants.models import Tenant, Domain

@extend_schema_view(
    login=extend_schema(
        summary="Obtain JWT tokens",
        request=LoginSerializer,
        responses={200: OpenApiResponse(response=LoginSerializer, description="Returns access & refresh tokens")},
    ),
    refresh=extend_schema(
        summary="Refresh access token",
        request=RefreshSerializer,
        responses={200: OpenApiResponse(response=RefreshSerializer, description="Returns new access token")},
    ),
    logout=extend_schema(
        summary="Logout & blacklist refresh token",
        request=LogoutSerializer,
        responses={200: None},
    ),
    create_tenant=extend_schema(
        summary="Onboard a new tenant",
        request=TenantCreateSerializer,
        responses={201: TenantCreateResponseSerializer},
    ),
)

class AuthViewSet(viewsets.GenericViewSet):
    """
    - POST /auth/login/         → issue JWTs as cookies
    - POST /auth/refresh/       → rotate access_token cookie
    - POST /auth/logout/        → blacklist + clear cookies
    - POST /auth/create_tenant/ → onboard a new tenant (atomic)
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes     = [AllowAny]

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def login(self, request):
        serializer = TokenObtainPairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens  = serializer.validated_data
        access  = tokens["access"]
        refresh = tokens["refresh"]

        resp = Response({"access": access}, status=status.HTTP_200_OK)
        resp.set_cookie(
            settings.SIMPLE_JWT["AUTH_COOKIE"],
            access,
            path="/",
            max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
        resp.set_cookie(
            settings.SIMPLE_JWT["REFRESH_COOKIE"],
            refresh,
            path="/",
            max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["REFRESH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["REFRESH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["REFRESH_COOKIE_SAMESITE"],
        )
        return resp

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def refresh(self, request):
        refresh_token = (
            request.data.get("refresh")
            or request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        )
        if not refresh_token:
            return Response(
                {"error": "No refresh token provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            return Response(
                {"error": "Invalid refresh token.", "details": str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )

        access = serializer.validated_data["access"]
        resp = Response({"access": access}, status=status.HTTP_200_OK)
        resp.set_cookie(
            settings.SIMPLE_JWT["AUTH_COOKIE"],
            access,
            path="/",
            max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
        return resp

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def logout(self, request):
        token = request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        if not token:
            return Response(
                {"error": "No refresh token in cookies."},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            RefreshToken(token).blacklist()
        except TokenError as e:
            return Response(
                {"error": "Failed to blacklist refresh token.", "details": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        resp = Response({"detail": "Logged out."}, status=status.HTTP_200_OK)
        resp.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"], path="/")
        resp.delete_cookie(settings.SIMPLE_JWT["REFRESH_COOKIE"], path="/")
        return resp

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def create_tenant(self, request):
        subdomain = (request.data.get("subdomain") or "").strip().lower()
        reserved = [name.lower() for name in settings.RESERVED_SUBDOMAINS]

        if not subdomain:
            return Response({"error": "Subdomain is required."},
                            status=status.HTTP_400_BAD_REQUEST)
        if subdomain in reserved:
            return Response(
                {"error": f"'{subdomain}' is a reserved subdomain."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not re.match(r"^[a-zA-Z0-9]+$", subdomain):
            return Response(
                {"error": "Subdomain must be alphanumeric."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if len(subdomain) > 50:
            return Response(
                {"error": "Subdomain too long (max 50 chars)."},
                status=status.HTTP_400_BAD_REQUEST
            )

        domain = f"{subdomain}.{settings.TENANT_SUBDOMAIN_BASE}"
        if Tenant.objects.filter(schema_name=subdomain).exists() or \
           Domain.objects.filter(domain=domain).exists():
            return Response(
                {"error": "Tenant/schema or domain already exists."},
                status=status.HTTP_409_CONFLICT
            )

        try:
            with transaction.atomic():
                tenant = Tenant(schema_name=subdomain, name=subdomain.capitalize())
                tenant.save()  # creates the new schema
                Domain.objects.create(
                    tenant=tenant,
                    domain=domain,
                    is_primary=True
                )
        except Exception as e:
            return Response(
                {"error": "Failed to create tenant record.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try:
            call_command(
                "migrate_schemas",
                schema_name=subdomain,
                interactive=False,
                verbosity=1
            )
        except Exception as e:
            tenant.delete()
            return Response(
                {"error": "Tenant onboarding failed during migration.",
                 "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response({
            "message": "Tenant onboarded successfully.",
            "schema": subdomain,
            "domain": domain
        }, status=status.HTTP_201_CREATED)