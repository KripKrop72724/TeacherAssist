import time
from django.conf import settings
import redis

_client = None
_memory = set()


def _get_client():
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.REDIS_URL)
    return _client


KEY_PREFIX = "blacklist:"


def blacklist_jti(jti: str, exp: int) -> None:
    ttl = int(exp - time.time())
    if ttl <= 0:
        return
    try:
        _get_client().setex(KEY_PREFIX + jti, ttl, "1")
    except Exception:
        _memory.add(jti)


def is_jti_blacklisted(jti: str) -> bool:
    try:
        return bool(_get_client().exists(KEY_PREFIX + jti))
    except Exception:
        return jti in _memory