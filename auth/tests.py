from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from types import SimpleNamespace
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from django.conf import settings

from auth.api_views import AuthViewSet
from auth.serializers import SchemaTokenObtainPairSerializer
from auth.authentication import CookieJWTAuthentication
from tenants.models import Tenant, Domain
from django_tenants.test.client import TenantClient

class SchemaTokenSerializerTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(
            username="tester", password="pass123"
        )

    def test_token_includes_schema(self):
        request = self.factory.post("/")
        request.tenant = SimpleNamespace(schema_name="tenant1")
        with patch(
            "rest_framework_simplejwt.token_blacklist.models.OutstandingToken.objects.create"
        ):
            ser = SchemaTokenObtainPairSerializer(
                data={"username": "tester", "password": "pass123"},
                context={"request": request},
            )
            self.assertTrue(ser.is_valid(), ser.errors)
            access = AccessToken(ser.validated_data["access"])
            self.assertEqual(access["schema"], "tenant1")


class CookieJWTAuthenticationTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(
            username="tester2", password="pass123"
        )

    def test_schema_mismatch_rejects_token(self):
        with patch(
            "rest_framework_simplejwt.token_blacklist.models.OutstandingToken.objects.create"
        ):
            token = RefreshToken.for_user(self.user)
        token["schema"] = "tenant1"
        access = token.access_token
        access["schema"] = "tenant1"

        request = self.factory.get("/")
        request.COOKIES = {settings.SIMPLE_JWT["AUTH_COOKIE"]: str(access)}
        request.tenant = SimpleNamespace(schema_name="tenant2")

        auth = CookieJWTAuthentication()
        with self.assertRaises(AuthenticationFailed):
            auth.authenticate(request)


class TenantValidationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.public_tenant = Tenant.objects.create(schema_name="public", name="Public")
        Domain.objects.create(tenant=self.public_tenant, domain="testserver", is_primary=True)

    def _create_domain(self, sub, base="example.com"):
        tenant = Tenant.objects.create(schema_name=sub, name=sub.capitalize())
        Domain.objects.create(tenant=tenant, domain=f"{sub}.{base}", is_primary=True)

    def test_check_tenant_flags_existing_prefix(self):
        self._create_domain("demo", base="other.com")
        url = reverse("auth:auth-check-tenant")
        resp = self.client.get(url, {"subdomain": "demo"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.data["available"])

    @override_settings(TENANT_CREATION_REQUIRE_CAPTCHA=False)
    def test_create_tenant_rejects_existing_prefix(self):
        self._create_domain("demo", base="other.com")
        with patch("auth.api_views.call_command"):
            url = reverse("auth:auth-create-tenant")
            resp = self.client.post(url, {"subdomain": "demo"})
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)


class CookieDomainTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        # create the demo tenant + domain once
        cls.tenant = Tenant.objects.create(schema_name="demo", name="Demo")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True
        )

    def setUp(self):
        super().setUp()
        # Override the default client with a TenantClient so we get schema_context()
        self.client = TenantClient(
            self.tenant,
            HTTP_HOST=f"demo.{settings.TENANT_SUBDOMAIN_BASE}"
        )

    @override_settings(COOKIE_DOMAIN=".test.com")
    def test_refresh_sets_domain(self):
        # Create a user in the tenant schema
        with self.client.schema_context():
            user = get_user_model().objects.create_user(
                username="u", password="p", email="u@example.com"
            )
            rt = RefreshToken.for_user(user)

        # Hit the refresh endpoint under that tenant
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(rt)},
            format="json"
        )
        self.assertEqual(resp.status_code, 200)
        auth_cookie = resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]]
        self.assertEqual(auth_cookie["domain"], settings.COOKIE_DOMAIN)
        refresh_cookie = resp.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]]
        self.assertEqual(refresh_cookie["domain"], settings.COOKIE_DOMAIN)

    @override_settings(COOKIE_DOMAIN=".test.com")
    def test_logout_deletes_domain(self):
        # Create & authenticate user in tenant
        with self.client.schema_context():
            user = get_user_model().objects.create_user(
                username="x", password="y", email="x@example.com"
            )
            rt = RefreshToken.for_user(user)

        # Log them in via the refresh cookie
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(rt)
        resp = self.client.post("/auth/logout/")
        self.assertEqual(resp.status_code, 200)
        auth_cookie = resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]]
        self.assertEqual(auth_cookie["domain"], settings.COOKIE_DOMAIN)
        refresh_cookie = resp.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]]
        self.assertEqual(refresh_cookie["domain"], settings.COOKIE_DOMAIN)