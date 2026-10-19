"""Bounded per-library snapshots of sparse facts in Seahub's Django cache.

ACL rules are sparse relative to library contents, so one read serves every
user and path for at most the TTL. Tags are deliberately NOT cached here.
A committed write switches the library generation: readers that started
earlier can only refill the abandoned namespace. Cache failure recomputes;
read failure propagates and is never cached.
"""
import logging
import time

from django.conf import settings

logger = logging.getLogger(__name__)


def ttl(setting, default):
    value = getattr(settings, setting, default) if settings.configured else 0
    if type(value) is not int or not 0 <= value <= 300:
        raise ValueError('invalid %s' % setting)
    return value


def invalidate(namespace, repo_id):
    from uuid import uuid4
    from django.core.cache import cache
    try:
        cache.set('%s:gen:%s' % (namespace, repo_id), uuid4().hex, None)
    except Exception:
        # Revocation/refresh then waits for the normal TTL, never longer.
        logger.warning('CloudFile %s cache invalidation failed for %s', namespace, repo_id)


def snapshot(namespace, repo_id, seconds, read, encode, decode):
    """Return read() for repo_id, shared for at most `seconds`.

    read() may return None ("over budget"); that marker is cached too.
    decode() must raise on a malformed entry, which is then overwritten.
    """
    key = None
    if seconds:
        from django.core.cache import cache
        try:
            generation = cache.get('%s:gen:%s' % (namespace, repo_id)) or '0'
            key = '%s:%s:%s' % (namespace, generation, repo_id)
            value = cache.get(key)
        except Exception:
            key = value = None
        try:
            now = time.time()
            if isinstance(value, dict) and set(value) == {'expires', 'data'} and now < value['expires'] <= now + seconds:
                return None if value['data'] is None else decode(value['data'])
        except Exception:
            pass
    started = time.time()
    data = read()
    if key is not None:
        try:
            # Expiry starts at the read, so a slow refill cannot extend staleness.
            cache.set(key, {'expires': started + seconds, 'data': None if data is None else encode(data)},
                      timeout=seconds)
        except Exception:
            pass
    return data
