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

KEY_PREFIX = "blacklist"

def _make_key(schema: str, jti: str) -> str:
    return f"{KEY_PREFIX}:{schema}:{jti}"

def blacklist_jti(jti: str, exp_timestamp: int, schema: str) -> None:
    """Store jti for the given tenant schema with a TTL matching its expiry."""
    ttl = int(exp_timestamp - time.time())
    if ttl > 0:
        _get_client().setex(_make_key(schema, jti), ttl, "1")

def is_jti_blacklisted(jti: str, schema: str) -> bool:
    """Return True if the jti for the tenant schema is present in Redis."""
    return bool(_get_client().exists(_make_key(schema, jti)))
