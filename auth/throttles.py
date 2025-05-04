from django.conf import settings
from rest_framework.throttling import ScopedRateThrottle

class ConditionalScopeThrottle(ScopedRateThrottle):
    """
    Respects the environment flags to turn throttling on/off per action.
    """
    def get_scope(self, request, view):
        action = getattr(view, "action", None)
        if action == "create_tenant" and not settings.TENANT_CREATION_THROTTLE_ENABLED:
            return None
        if action == "check_tenant" and not settings.TENANT_CHECK_THROTTLE_ENABLED:
            return None
        if action == "register" and not settings.REGISTER_THROTTLE_ENABLED:
            return None
        return action