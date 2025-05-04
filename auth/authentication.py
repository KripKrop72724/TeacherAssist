from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import AuthenticationFailed

class CookieJWTAuthentication(JWTAuthentication):
    """
    1) Tries Authorization header first, then falls back to access_token cookie.
    2) Returns a standard 'Bearer' WWW-Authenticate header on 401.
    3) Converts InvalidToken → AuthenticationFailed for consistency.
    """
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            raw_token = request.COOKIES.get(self.get_cookie_name())
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), validated_token
        except InvalidToken as e:
            raise AuthenticationFailed(str(e))

    def authenticate_header(self, request):
        return "Bearer"

    @classmethod
    def get_cookie_name(cls):
        from django.conf import settings
        return settings.SIMPLE_JWT["AUTH_COOKIE"]

