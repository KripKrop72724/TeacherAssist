from django.db import connection
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django_tenants.utils import tenant_context
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from types import SimpleNamespace
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from auth.csrf import generate_csrf_token
from django.conf import settings
from auth.blacklist import blacklist_jti, is_jti_blacklisted
import time
import pyotp
from pathlib import Path
import json
from unittest.mock import MagicMock
import requests
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
        # Make sure we’re back in the public schema before creating any tenants
        connection.set_schema_to_public()
        self.client = APIClient()
        self.public_tenant = Tenant.objects.create(
            schema_name="public",
            name="Public",
        )
        Domain.objects.create(
            tenant=self.public_tenant,
            domain="testserver",
            is_primary=True,
        )

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
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        with patch("auth.api_views.call_command"):
            url = reverse("auth:auth-create-tenant")
            resp = self.client.post(url, {"subdomain": "demo"})
            resp = self.client.post(
                url,
                {"subdomain": "demo"},
                HTTP_X_CSRFTOKEN=token,
            )
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
        # use TenantClient so HTTP_HOST routing happens automatically
        self.client = TenantClient(
            self.tenant,
            HTTP_HOST=f"demo.{settings.TENANT_SUBDOMAIN_BASE}"
        )

    @override_settings(COOKIE_DOMAIN=".test.com")
    def test_refresh_sets_domain(self):
        # Build a user & refresh token _inside_ the demo schema:
        with tenant_context(self.tenant):
            user = get_user_model().objects.create_user(
                username="u", password="p", email="u@example.com"
            )
            rt = RefreshToken.for_user(user)

        # Now call /auth/refresh/ under that tenant:
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, 200)

        auth_cookie = resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]]
        self.assertEqual(auth_cookie["domain"], settings.COOKIE_DOMAIN)

        refresh_cookie = resp.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]]
        self.assertEqual(refresh_cookie["domain"], settings.COOKIE_DOMAIN)

    @override_settings(COOKIE_DOMAIN=".test.com")
    def test_logout_deletes_domain(self):
        # Build & authenticate a user _inside_ the demo schema:
        with tenant_context(self.tenant):
            user = get_user_model().objects.create_user(
                username="x", password="y", email="x@example.com"
            )
            rt = RefreshToken.for_user(user)

        # Pump the refresh cookie in, then hit logout:
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(rt)
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, 200)
        auth_cookie = resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]]
        self.assertEqual(auth_cookie["domain"], settings.COOKIE_DOMAIN)
        refresh_cookie = resp.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]]
        self.assertEqual(refresh_cookie["domain"], settings.COOKIE_DOMAIN)


class CsrfRequiredTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.public_tenant, _ = Tenant.objects.get_or_create(schema_name="public", defaults={"name": "Public"})
        Domain.objects.get_or_create(
            tenant=cls.public_tenant,
            domain="testserver",
            defaults={"is_primary": True},
        )
        cls.tenant = Tenant.objects.create(schema_name="demo2", name="Demo2")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo2.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )

    def setUp(self):
        super().setUp()
        self.client = TenantClient(
            self.tenant,
            HTTP_HOST=f"demo2.{settings.TENANT_SUBDOMAIN_BASE}",
        )

    def _create_user_with_rt(self):
        with tenant_context(self.tenant):
            user = get_user_model().objects.create_user(
                username="a", password="b", email="a@example.com"
            )
            return RefreshToken.for_user(user)

    def test_refresh_without_csrf_fails(self):
        rt = self._create_user_with_rt()
        resp = self.client.post("/auth/refresh/", {"refresh": str(rt)}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_refresh_mismatched_token_fails(self):
        rt = self._create_user_with_rt()
        cookie_token = generate_csrf_token()
        header_token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = cookie_token
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(rt)},
            format="json",
            HTTP_X_CSRFTOKEN=header_token,
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_refresh_matching_token_succeeds(self):
        rt = self._create_user_with_rt()
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_logout_without_csrf_fails(self):
        rt = self._create_user_with_rt()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(rt)
        resp = self.client.post("/auth/logout/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_logout_mismatched_token_fails(self):
        rt = self._create_user_with_rt()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(rt)
        cookie_token = generate_csrf_token()
        header_token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = cookie_token
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=header_token)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_logout_matching_token_succeeds(self):
        rt = self._create_user_with_rt()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(rt)
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    @override_settings(TENANT_CREATION_REQUIRE_CAPTCHA=False)
    def test_create_tenant_requires_csrf(self):
        connection.set_schema_to_public()
        resp = APIClient().post(reverse("auth:auth-create-tenant"), {"subdomain": "x"})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


class BlacklistIsolationTests(TestCase):
    def test_isolation_across_schemas(self):
        jti = "dummyjti"
        now = time.time() + 60
        blacklist_jti(jti, now, "tenant1")
        self.assertTrue(is_jti_blacklisted(jti, "tenant1"))
        self.assertFalse(is_jti_blacklisted(jti, "tenant2"))

class LoginFlowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.tenant = Tenant.objects.create(schema_name="demo3", name="Demo3")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo3.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )
        with tenant_context(cls.tenant):
            cls.user = get_user_model().objects.create_user(
                username="alice", password="pass123", email="a@example.com"
            )

    def setUp(self):
        self.client = TenantClient(
            self.tenant, HTTP_HOST=f"demo3.{settings.TENANT_SUBDOMAIN_BASE}"
        )

    def test_login_success_sets_cookies(self):
        resp = self.client.post(
            "/auth/login/",
            {"username": "alice", "password": "pass123"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertIn(settings.SIMPLE_JWT["AUTH_COOKIE"], resp.cookies)
        self.assertIn(settings.SIMPLE_JWT["REFRESH_COOKIE"], resp.cookies)
        self.assertIn(settings.CSRF_COOKIE_NAME, resp.cookies)

    def test_login_requires_otp(self):
        with tenant_context(self.tenant):
            from auth.models import TwoFactor
            tf, _ = TwoFactor.objects.get_or_create(
                user=self.user, defaults={"secret": pyotp.random_base32()}
            )
            tf.enabled = True
            tf.save(update_fields=["enabled"])

        resp = self.client.post(
            "/auth/login/",
            {"username": "alice", "password": "pass123"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.json(), {"otp_required": True})

    def test_login_invalid_otp(self):
        with tenant_context(self.tenant):
            from auth.models import TwoFactor
            tf, _ = TwoFactor.objects.get_or_create(
                user=self.user, defaults={"secret": pyotp.random_base32(), "enabled": True}
            )
            tf.enabled = True
            tf.save(update_fields=["enabled"])

        resp = self.client.post(
            "/auth/login/",
            {"username": "alice", "password": "pass123", "otp": "000000"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_valid_otp(self):
        with tenant_context(self.tenant):
            from auth.models import TwoFactor
            tf, _ = TwoFactor.objects.get_or_create(
                user=self.user, defaults={"secret": pyotp.random_base32()}
            )
            tf.enabled = True
            tf.save(update_fields=["enabled"])
            otp = tf.get_totp().now()

        resp = self.client.post(
            "/auth/login/",
            {"username": "alice", "password": "pass123", "otp": otp},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_login_invalid_credentials(self):
        resp = self.client.post(
            "/auth/login/",
            {"username": "alice", "password": "wrong"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class RefreshFlowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.tenant = Tenant.objects.create(schema_name="demo4", name="Demo4")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo4.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )
        with tenant_context(cls.tenant):
            cls.user = get_user_model().objects.create_user(
                username="bob", password="pass123", email="b@example.com"
            )

    def setUp(self):
        self.client = TenantClient(
            self.tenant, HTTP_HOST=f"demo4.{settings.TENANT_SUBDOMAIN_BASE}"
        )
        with tenant_context(self.tenant):
            self.rt = RefreshToken.for_user(self.user)

    def _csrf(self):
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        return token

    def test_refresh_with_body_token(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(self.rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_refresh_with_cookie_token(self):
        token = self._csrf()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(self.rt)
        resp = self.client.post("/auth/refresh/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_refresh_missing_token(self):
        token = self._csrf()
        resp = self.client.post("/auth/refresh/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_invalid_token(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": "bad"},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_reuse_blacklisted(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(self.rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(self.rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    @override_settings(COOKIE_DOMAIN=".example.com")
    def test_refresh_cookie_properties(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/refresh/",
            {"refresh": str(self.rt)},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        ac = resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]]
        self.assertEqual(ac["domain"], settings.COOKIE_DOMAIN)
        self.assertEqual(ac["httponly"], settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"])
        rc = resp.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]]
        self.assertEqual(rc["domain"], settings.COOKIE_DOMAIN)


class LogoutFlowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.tenant = Tenant.objects.create(schema_name="demo5", name="Demo5")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo5.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )
        with tenant_context(cls.tenant):
            cls.user = get_user_model().objects.create_user(
                username="carol", password="pass123", email="c@example.com"
            )
            cls.rt = RefreshToken.for_user(cls.user)

    def setUp(self):
        self.client = TenantClient(
            self.tenant, HTTP_HOST=f"demo5.{settings.TENANT_SUBDOMAIN_BASE}"
        )

    def _csrf(self):
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        return token

    def test_logout_valid(self):
        token = self._csrf()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = str(self.rt)
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        jti = self.rt["jti"]
        self.assertTrue(is_jti_blacklisted(jti, self.tenant.schema_name))
        self.assertEqual(resp.cookies[settings.SIMPLE_JWT["AUTH_COOKIE"]].value, "")

    def test_logout_missing_cookie(self):
        token = self._csrf()
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_invalid_token(self):
        token = self._csrf()
        self.client.cookies[settings.SIMPLE_JWT["REFRESH_COOKIE"]] = "bad"
        resp = self.client.post("/auth/logout/", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class RegisterFlowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.tenant = Tenant.objects.create(schema_name="demo6", name="Demo6")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo6.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )
        with tenant_context(cls.tenant):
            cls.existing = get_user_model().objects.create_user(
                username="exists", password="pass123", email="exists@example.com"
            )

    def setUp(self):
        self.client = TenantClient(
            self.tenant, HTTP_HOST=f"demo6.{settings.TENANT_SUBDOMAIN_BASE}"
        )

    def _csrf(self):
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        return token

    def test_register_success(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/register/",
            {
                "username": "newuser",
                "email": "new@example.com",
                "password": "pass12345",
                "password2": "pass12345",
            },
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn(settings.CSRF_COOKIE_NAME, resp.cookies)

    def test_register_duplicate_username(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/register/",
            {
                "username": "exists",
                "email": "other@example.com",
                "password": "pass12345",
                "password2": "pass12345",
            },
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_password_mismatch(self):
        token = self._csrf()
        resp = self.client.post(
            "/auth/register/",
            {
                "username": "x",
                "email": "x@example.com",
                "password": "pass12345",
                "password2": "pass000",
            },
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class TenantCreationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.client = APIClient()
        cls.public = Tenant.objects.create(schema_name="public", name="Public")
        Domain.objects.create(tenant=cls.public, domain="testserver", is_primary=True)

    def _csrf(self):
        token = generate_csrf_token()
        self.client.cookies[settings.CSRF_COOKIE_NAME] = token
        return token

    def test_check_tenant_available(self):
        resp = self.client.get(reverse("auth:auth-check-tenant"), {"subdomain": "fresh"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.data["available"])

    def test_check_tenant_reserved(self):
        resp = self.client.get(reverse("auth:auth-check-tenant"), {"subdomain": settings.RESERVED_SUBDOMAINS[0]})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.data["available"])

    def test_check_tenant_missing(self):
        resp = self.client.get(reverse("auth:auth-check-tenant"))
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(TENANT_CREATION_REQUIRE_CAPTCHA=False)
    def test_create_tenant_success(self):
        token = self._csrf()
        with patch("auth.api_views.call_command"):
            resp = self.client.post(
                reverse("auth:auth-create-tenant"),
                {"subdomain": "fresh"},
                HTTP_X_CSRFTOKEN=token,
            )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    @override_settings(TENANT_CREATION_REQUIRE_CAPTCHA=False)
    def test_create_tenant_reserved(self):
        token = self._csrf()
        with patch("auth.api_views.call_command"):
            resp = self.client.post(
                reverse("auth:auth-create-tenant"),
                {"subdomain": settings.RESERVED_SUBDOMAINS[0]},
                HTTP_X_CSRFTOKEN=token,
            )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(TENANT_CREATION_REQUIRE_CAPTCHA=True)
    def test_create_tenant_recaptcha_failure(self):
        token = self._csrf()
        with patch("auth.api_views.requests.post", side_effect=requests.RequestException("boom")):
            resp = self.client.post(
                reverse("auth:auth-create-tenant"),
                {"subdomain": "fresh", "recaptcha_token": "abc"},
                HTTP_X_CSRFTOKEN=token,
            )
        self.assertEqual(resp.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)


class TwoFactorTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        connection.set_schema_to_public()
        cls.tenant = Tenant.objects.create(schema_name="demo7", name="Demo7")
        Domain.objects.create(
            tenant=cls.tenant,
            domain=f"demo7.{settings.TENANT_SUBDOMAIN_BASE}",
            is_primary=True,
        )
        with tenant_context(cls.tenant):
            cls.user = get_user_model().objects.create_user(
                username="tf", password="pass123", email="tf@example.com"
            )

    def _force_auth(self, method, path, data=None, **kwargs):
        factory = APIRequestFactory()
        request = getattr(factory, method)(path, data=data, **kwargs)
        request.tenant = self.tenant
        force_authenticate(request, user=self.user)
        view = AuthViewSet.as_view({method: path.split('/')[-2]})
        with tenant_context(self.tenant):
            return view(request)

    def test_setup_idempotent(self):
        resp1 = self._force_auth("get", "/auth/two_factor_setup/")
        resp2 = self._force_auth("get", "/auth/two_factor_setup/")
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp1.data["secret"], resp2.data["secret"])

    def test_enable_and_disable(self):
        setup = self._force_auth("get", "/auth/two_factor_setup/")
        otp = pyotp.TOTP(setup.data["secret"]).now()
        token = generate_csrf_token()
        req = APIRequestFactory().post(
            "/auth/two_factor_enable/",
            {"otp": otp},
            HTTP_X_CSRFTOKEN=token,
        )
        req.tenant = self.tenant
        req.COOKIES[settings.CSRF_COOKIE_NAME] = token
        force_authenticate(req, user=self.user)
        view = AuthViewSet.as_view({"post": "two_factor_enable"})
        resp = view(req)
        self.assertEqual(resp.status_code, 200)

        otp2 = pyotp.TOTP(setup.data["secret"]).now()
        req2 = APIRequestFactory().post(
            "/auth/two_factor_disable/",
            {"otp": otp2},
            HTTP_X_CSRFTOKEN=token,
        )
        req2.tenant = self.tenant
        req2.COOKIES[settings.CSRF_COOKIE_NAME] = token
        force_authenticate(req2, user=self.user)
        view2 = AuthViewSet.as_view({"post": "two_factor_disable"})
        resp2 = view2(req2)
        self.assertEqual(resp2.status_code, 200)


class JWKSViewTests(TestCase):
    def setUp(self):
        connection.set_schema_to_public()
        self.public_tenant, _ = Tenant.objects.get_or_create(
            schema_name="public", defaults={"name": "Public"}
        )
        Domain.objects.get_or_create(
            tenant=self.public_tenant,
            domain="testserver",
            defaults={"is_primary": True},
        )
        Path("public.pem").write_text(Path("public.pem").read_text())
        self.client = TenantClient(self.public_tenant, HTTP_HOST="testserver")

    def test_jwks_fetch(self):
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("keys", resp.json())


class CookieJWTAuthenticationHeaderTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(username="authu", password="pass")

    def _token(self):
        token = RefreshToken.for_user(self.user)
        token["schema"] = "s1"
        access = token.access_token
        access["schema"] = "s1"
        return access

    def test_header_token_auth(self):
        access = self._token()
        request = self.factory.get("/")
        request.headers = {"Authorization": f"Bearer {access}"}
        request.tenant = SimpleNamespace(schema_name="s1")
        user, _ = CookieJWTAuthentication().authenticate(request)
        self.assertEqual(user, self.user)

    def test_cookie_token_auth(self):
        access = self._token()
        request = self.factory.get("/")
        request.COOKIES = {settings.SIMPLE_JWT["AUTH_COOKIE"]: str(access)}
        request.tenant = SimpleNamespace(schema_name="s1")
        user, _ = CookieJWTAuthentication().authenticate(request)
        self.assertEqual(user, self.user)