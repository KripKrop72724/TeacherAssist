from django.conf import settings
from rest_framework.throttling import ScopedRateThrottle

class ConditionalScopeThrottle(ScopedRateThrottle):
    """
    Honors the throttle_scope on the action decorator,
    but skips throttling if the corresponding env flag is False.
    """
    def allow_request(self, request, view):
        scope = getattr(view, 'throttle_scope', None)
        if scope == 'tenant_creation' and not settings.TENANT_CREATION_THROTTLE_ENABLED:
            return True
        if scope == 'tenant_check'    and not settings.TENANT_CHECK_THROTTLE_ENABLED:
            return True
        return super().allow_request(request, view)