"""Isolated real-DRF/V2 contract tests; no native service or database required."""
import sys
import types
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from django.conf import settings
settings.configure(SECRET_KEY='isolated-contract-test', INSTALLED_APPS=[],
    REST_FRAMEWORK={'UNAUTHENTICATED_USER': None, 'DEFAULT_AUTHENTICATION_CLASSES': []},
    DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.dummy.DummyCache'}})
import django
django.setup()
from rest_framework.authentication import BaseAuthentication, SessionAuthentication
# Only native account/database transport imports are isolated here. DRF and
# CloudFile HTTP, Authority, path validation and sparse ACL resolver are real.
auth = types.ModuleType('seahub.api2.authentication')
auth.TokenAuthentication = BaseAuthentication
auth.SessionAuthentication = SessionAuthentication
sys.modules[auth.__name__] = auth
utils = types.ModuleType('seahub.api2.utils')
utils.JWT_PRIVATE_KEY = 'isolated-native-test-secret'
sys.modules[utils.__name__] = utils
suite = unittest.TestSuite()
for name in ('cloudfile_ext.v2.tests.test_effective_contract',
             'cloudfile_ext.v2.tests.test_acl_runtime',
             'cloudfile_ext.v2.tests.test_acl_policy',
             'cloudfile_ext.v2.tests.test_acl_http.HTTPTests.test_effective_is_bound_to_authenticated_user',
             'cloudfile_ext.v2.tests.test_acl_http.HTTPTests.test_subject_or_sql_outage_is_not_native_fallback'):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
