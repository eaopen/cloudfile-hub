"""Fixed session actor boundaries; not native DB or signed-session evidence."""
import ast
from pathlib import Path
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.native_session import BACKEND
from cloudfile_extensions.identity.read_ticket_http import native_download_actor


class DownloadActorTests(unittest.TestCase):
    def test_native_type_and_session_identity_required_before_reload(self):
        # Exercise the actual User class without importing Seahub's native
        # process, LDAP, account models or database during an isolated check.
        root = Path(__file__).resolve().parents[2]
        source = root / 'seahub/base/accounts.py'
        tree = ast.parse(source.read_text())
        user_class = next(node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == 'User')
        namespace = dict(UserManager=lambda: None, UserPermissions=lambda user: None,
            AdminPermissions=lambda user: None)
        exec(compile(ast.Module(body=[user_class], type_ignores=[]), str(source), 'exec'), namespace)
        User = namespace['User']
        auth = types.ModuleType('seahub.auth')
        for node in ast.parse((root / 'seahub/auth/__init__.py').read_text()).body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in {'BACKEND_SESSION_KEY', 'SESSION_KEY'}:
                    setattr(auth, name, ast.literal_eval(node.value))
        BACKEND_SESSION_KEY, SESSION_KEY = auth.BACKEND_SESSION_KEY, auth.SESSION_KEY
        accounts = types.ModuleType('seahub.base.accounts')
        accounts.User = User
        profiles = types.ModuleType('seahub.profile.models')
        profiles.Profile = SimpleNamespace(objects=SimpleNamespace(
            get=lambda **kwargs: self.fail('invalid actor reached profile lookup')))
        package = types.ModuleType('seahub')
        package.__path__ = [str(root / 'seahub')]
        modules = {'seahub': package, 'seahub.auth': auth,
            'seahub.base.accounts': accounts, 'seahub.profile.models': profiles}
        with patch.dict(sys.modules, modules):
            self.check_invalid_actors(User, BACKEND_SESSION_KEY, SESSION_KEY)

    def check_invalid_actors(self, User, BACKEND_SESSION_KEY, SESSION_KEY):
        for fixture in ("fake", "missing", "wrong-name", "wrong-backend", "inactive"):
            with self.subTest(fixture=fixture):
                user = User("native-user")
                user.is_active = fixture != "inactive"
                session = {BACKEND_SESSION_KEY: BACKEND, SESSION_KEY: "native-user"}
                if fixture == "fake":
                    user = SimpleNamespace(username="native-user", is_active=True, is_authenticated=True)
                elif fixture == "missing":
                    session = None
                elif fixture == "wrong-name":
                    session[SESSION_KEY] = "another-user"
                elif fixture == "wrong-backend":
                    session[BACKEND_SESSION_KEY] = "another-backend"
                request = SimpleNamespace(user=user, session=session, is_secure=lambda: True)
                with patch("cloudfile_extensions.identity.read_ticket_http.CloudFileOIDCBackend") as backend:
                    with self.assertRaises(ContractError):
                        native_download_actor(request)
                    backend.assert_not_called()
