from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings

from auth.serializers import SchemaTokenObtainPairSerializer
from auth.authentication import CookieJWTAuthentication


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