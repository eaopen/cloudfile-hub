"""Native service/ORM doubles for fast tests, never loaded by integration CI.

Keep real Django/DRF request, permission and CSRF handling. Only native account,
RPC and ORM boundaries are doubled; tests must explicitly configure their calls.
"""
import ast
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import Mock
from urllib.parse import quote


def install(native_root=None):
    from django.conf import settings
    if not settings.configured:
        settings.configure(SECRET_KEY='isolated-contract-key-not-for-deployment',
            ALLOWED_HOSTS=['testserver'], THUMBNAIL_ROOT='/tmp', THUMBNAIL_DEFAULT_SIZE=64, ENABLE_THUMBNAIL_SERVER=False, SERVICE_URL='https://files.example/', DEFAULT_CHARSET='utf-8', INSTALLED_APPS=[],
            REST_FRAMEWORK={'UNAUTHENTICATED_USER': None}, SITE_ROOT='/', ENABLE_OAUTH=True,
            OAUTH_CLIENT_ID='fixture', OAUTH_CLIENT_SECRET='fixture',
            OAUTH_AUTHORIZATION_URL='https://idp.example/authorize',
            OAUTH_REDIRECT_URL='https://files.example/callback',
            OAUTH_TOKEN_URL='https://idp.example/token',
            OAUTH_USER_INFO_URL='https://idp.example/userinfo',
            OAUTH_SCOPE='openid profile', OAUTH_PROVIDER='fixture')
    import django
    django.setup()
    from rest_framework.authentication import BaseAuthentication, SessionAuthentication
    from rest_framework.response import Response
    from rest_framework.views import APIView

    root = Path(native_root) if native_root else Path(__file__).resolve().parents[1]

    def module(name, **values):
        obj = ModuleType(name)
        obj.__dict__.update(values)
        path = root.joinpath(*name.split('.'))
        if path.is_dir():
            obj.__path__ = [str(path)]
        sys.modules[name] = obj
        parent, _, child = name.rpartition('.')
        if parent in sys.modules:
            setattr(sys.modules[parent], child, obj)
        return obj

    def boundary(name):
        # Unexpected native I/O fails loudly instead of succeeding via a Mock.
        class Boundary:
            def __getattr__(self, operation):
                value = Mock(name=name + '.' + operation,
                    side_effect=AssertionError('Unconfigured native boundary: ' + name + '.' + operation))
                setattr(self, operation, value)
                return value
        return Boundary()

    def model(name):
        return type(name, (), {'objects': boundary(name), 'DoesNotExist': type('DoesNotExist', (Exception,), {})})

    class TokenAuthentication(BaseAuthentication):
        def authenticate(self, request):
            # Native token verification belongs to the full runtime suite;
            # unforced requests remain anonymous, never implicitly trusted.
            return None

    for name in ('seahub', 'seahub.api2', 'seahub.base', 'seahub.profile',
                 'seahub.auth', 'seahub.tags', 'seahub.repo_tags', 'seahub.file_tags',
                 'seahub.share', 'seahub.role_permissions'):
        module(name)
    sys.modules['seahub.settings'] = settings
    sys.modules['seahub'].settings = settings
    module('pysearpc', SearpcError=type('SearpcError', (Exception,), {}))
    module('seaserv', seafile_api=boundary('seafile_api'), ccnet_api=boundary('ccnet_api'))
    module('seahub.api2.authentication', SessionCRSFCheckFreeAuthentication=SessionAuthentication, TokenAuthentication=TokenAuthentication,
           SessionAuthentication=SessionAuthentication)
    module('seahub.api2.base', APIView=APIView)
    module('seahub.api2.utils', JWT_PRIVATE_KEY=settings.SECRET_KEY,
           api_error=lambda status, message: Response({'error_msg': message}, status=status),
           get_api_token=boundary('get_api_token'), is_valid_internal_jwt=boundary('is_valid_internal_jwt'),
           get_user_common_info=boundary('get_user_common_info'))
    module('seahub.base.accounts', User=model('User'))
    module('seahub.profile.models', Profile=model('Profile'))
    module('seahub.auth.models', SocialAuthUser=model('SocialAuthUser'))
    for name in ('authenticate', 'login', 'logout'):
        setattr(sys.modules['seahub.auth'], name, boundary('auth.' + name))
    for package, names in [('tags', ('FileTag', 'FileUUIDMap')), ('repo_tags', ('RepoTags',)),
                           ('file_tags', ('FileTags',))]:
        module('seahub.' + package + '.models', **{name: model(name) for name in names})
    module('seahub.views', check_folder_permission=boundary('check_folder_permission'))
    module('seahub.share.utils', is_repo_admin=boundary('is_repo_admin'))
    module('seahub.role_permissions.utils', get_enabled_role_permissions_by_role=boundary('role_permissions'))
    utils = module('seahub.utils', quote=quote,
        get_fileserver_root=lambda: 'http://files.example/seafhttp',
        is_valid_email=boundary('is_valid_email'), render_error=boundary('render_error'),
        get_service_url=boundary('get_service_url'))
    # Execute the actual production utility functions rather than copies.
    for path, target, names in [
        ('seahub/utils/__init__.py', utils, {'normalize_dir_path', 'normalize_file_path', 'normalize_cache_key', 'gen_file_get_url'}),
        ('seahub/api2/utils.py', sys.modules['seahub.api2.utils'], {'to_python_boolean'})]:
        nodes = [n for n in ast.parse((root / path).read_text()).body
                 if isinstance(n, ast.FunctionDef) and n.name in names]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), path, 'exec'), target.__dict__)
    module('seahub.utils.file_size', get_quota_from_string=boundary('get_quota_from_string'))

    # Leaf CE view imports pull in unrelated native models and services. Provide
    # only their named boundaries; the view implementations themselves are real.
    keep = {'seahub.api2.authentication', 'seahub.api2.throttling', 'seahub.api2.utils',
            'seahub.settings', 'seahub.constants', 'seahub.utils.timeutils',
            'seahub.utils.file_types', 'seahub.utils', 'seahub.base.accounts'}
    for relative in ('seahub/api2/endpoints/dir.py', 'seahub/api2/endpoints/internal_api.py'):
        for node in ast.parse((root / relative).read_text()).body:
            if not isinstance(node, ast.ImportFrom) or not node.module or not node.module.startswith('seahub.'):
                continue
            if node.module in keep:
                continue
            if node.module not in sys.modules:
                module(node.module)
            target = sys.modules[node.module]
            for alias in node.names:
                if not hasattr(target, alias.name):
                    setattr(target, alias.name, boundary(node.module + '.' + alias.name))
    utils.check_filename_with_rename = boundary('check_filename_with_rename')
    utils.is_valid_dirent_name = boundary('is_valid_dirent_name')
    utils.is_pro_version = lambda: False
    utils.FILEEXT_TYPE_MAP = {}
    utils.get_file_type_and_ext = boundary('get_file_type_and_ext')
    sys.modules['seahub.auth'].REDIRECT_FIELD_NAME = 'next'

    # Display-only CE preview types are configured by individual cases; the
    # default empty collection never bypasses native download permissions.
    sys.modules['seahub.views.file'].FILE_TYPE_FOR_NEW_FILE_LINK = ()
