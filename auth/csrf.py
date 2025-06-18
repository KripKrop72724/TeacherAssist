import secrets
import hmac
from django.conf import settings
from rest_framework.permissions import BasePermission


class DoubleSubmitCSRF(BasePermission):
    """Simple double-submit CSRF protection."""

    message = "CSRF token missing or invalid."

    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        cookie_token = request.COOKIES.get(settings.CSRF_COOKIE_NAME)
        header_token = request.headers.get("X-CSRFToken")
        if not cookie_token or not header_token:
            return False
        return hmac.compare_digest(str(cookie_token), str(header_token))


def generate_csrf_token():
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response, token=None):
    token = token or generate_csrf_token()
    secure = getattr(
        settings, "CSRF_COOKIE_SECURE", settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"]
    )
    samesite = getattr(settings, "CSRF_COOKIE_SAMESITE", "Lax")
    max_age = int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())
    response.set_cookie(
        settings.CSRF_COOKIE_NAME,
        token,
        domain=settings.COOKIE_DOMAIN,
        path="/",
        secure=secure,
        httponly=False,
        samesite=samesite,
        max_age=max_age,
    )
    return token