"""Fixed session actor boundaries; not native DB or signed-session evidence."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.native_session import BACKEND
from cloudfile_extensions.identity.read_ticket_http import native_download_actor


class DownloadActorTests(unittest.TestCase):
    def test_native_type_and_session_identity_required_before_reload(self):
        from seahub.auth import BACKEND_SESSION_KEY, SESSION_KEY
        from seahub.base.accounts import User
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
