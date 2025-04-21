from django.conf import settings
from drf_spectacular.extensions import OpenApiAuthenticationExtension

class CookieJWTScheme(OpenApiAuthenticationExtension):
    """
    Maps CookieJWTAuthentication → an apiKey-in-cookie security scheme.
    """
    target_class = 'auth.authentication.CookieJWTAuthentication'
    name         = 'cookieJWT'
    match_subclasses = True

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in':   'cookie',
            'name': settings.SIMPLE_JWT['AUTH_COOKIE'],
        }
