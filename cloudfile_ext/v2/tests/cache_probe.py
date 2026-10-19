"""Disposable subprocess probe for Django on_commit and Redis worker sharing."""
import json
import os
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from django.conf import settings

settings.configure(
    SECRET_KEY='cache-test-only',
    INSTALLED_APPS=[],
    DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    CACHES={'default': {
        'BACKEND': ('django.core.cache.backends.redis.RedisCache' if
                    os.environ.get('CF_V2_REDIS_URL') else
                    'django.core.cache.backends.locmem.LocMemCache'),
        'LOCATION': os.environ.get('CF_V2_REDIS_URL', 'callback-test')}},
)
import django
django.setup()

from django.core.cache import cache
from django.db import transaction
from cloudfile_ext.v2 import library_cache

ACTION = sys.argv[1]


def callback_check():
    from cloudfile_ext.v2.acl_runtime import store
    fake = ModuleType('seahub.utils.db_api')
    fake.SeafileDB = lambda: SimpleNamespace(db_name='cf_test')
    with patch.dict(sys.modules, {'seahub.utils.db_api': fake}):
        changed = store().changed
    repo = sys.argv[2]
    generation = 'cf-acl-rules-v1:gen:' + repo
    try:
        with transaction.atomic():
            changed(repo)
            raise RuntimeError('rollback outer atomic')
    except RuntimeError:
        pass
    rolled_back = cache.get(generation)
    with transaction.atomic():
        changed(repo)
    committed = cache.get(generation)
    print(json.dumps({'rollback_kept_generation': rolled_back is None,
                      'commit_switched_generation': isinstance(committed, str) and len(committed) == 32}))


def read_or_invalidate():
    namespace, repo_id = 'v2-cache-test', sys.argv[2]
    if ACTION == 'invalidate':
        library_cache.invalidate(namespace, repo_id)
        print(json.dumps({'pid': os.getpid(), 'invalidated': True}))
        return
    incoming = sys.argv[3]
    result = library_cache.snapshot(namespace, repo_id, 180, lambda: [incoming],
                                    lambda x: x, lambda x: x)
    print(json.dumps({'pid': os.getpid(), 'value': result}))


if ACTION == 'callback':
    callback_check()
else:
    read_or_invalidate()
