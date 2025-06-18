from django.apps import AppConfig


class AuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth'
    label = 'auth_module'

    def ready(self):
        import auth.blacklist as rb
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import TokenError

        def _outstanding(self):
            return None

        def _blacklist(self):
            jti = self.get("jti")
            exp = self.get("exp")
            schema = self.get("schema")
            rb.blacklist_jti(jti, exp, schema)

        def _check(self):
            jti = self.get("jti")
            schema = self.get("schema")
            if rb.is_jti_blacklisted(jti, schema):
                raise TokenError("Token is blacklisted")

        RefreshToken.outstanding      = _outstanding
        RefreshToken.outstand         = _outstanding
        RefreshToken.blacklist        = _blacklist
        RefreshToken.check_blacklist  = _check