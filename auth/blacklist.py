# auth/redis_blacklist.py
import time
import redis
from django.conf import settings

_client = None

def _get_client():
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.REDIS_URL)
    return _client

KEY_PREFIX = "blacklist:"

def blacklist_jti(jti: str, exp_timestamp: int) -> None:
    """
    Store jti in Redis with a TTL that matches its expiry.
    """
    ttl = int(exp_timestamp - time.time())
    if ttl > 0:
        _get_client().setex(KEY_PREFIX + jti, ttl, "1")

def is_jti_blacklisted(jti: str) -> bool:
    """
    Returns True if that jti is in the Redis set (i.e. we told Redis to expire it).
    """
    return bool(_get_client().exists(KEY_PREFIX + jti))
