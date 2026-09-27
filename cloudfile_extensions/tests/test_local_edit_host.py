"""Local-edit request ownership and post-fork proxy coverage."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.authorization.deployment import configure_policy
from cloudfile_extensions.authorization.host import PolicyHost
from cloudfile_extensions.local_edit import gunicorn


class _AgentRuntime:
    def __init__(self):
        self.host = None

    def challenge(self, value, request_id):
        if self.host.active != 1:
            raise AssertionError("agent operation is outside host ownership")
        return {"value": value, "request_id": request_id}


class LocalEditHostTest(unittest.TestCase):
    @staticmethod
    def config():
        return dict(database=dict(host="db", user="cloudfile", name="cloudfile", password="secret"),
            redis=dict(host="redis", port=6379, password="secret"), provider="fixture",
            native_schema="ccnet", identity_schema="cloudfile", directory_url="https://directory.invalid/",
            attribute_allowlist=[], core_library="libcloudfile_acl.so", cloud_mode=False)

    def host(self):
        @contextmanager
        def sessions(request, request_id):
            yield (request, request_id)

        runtime = _AgentRuntime()
        deployment = SimpleNamespace(local_session_factory=sessions,
            local_device_factory=None, local_agent_runtime=runtime,
            local_read_issuer=None, close=Mock())
        with patch("cloudfile_extensions.authorization.host.configure_policy", return_value=deployment):
            host = PolicyHost({}, directory_authorization=Mock())
        runtime.host = host
        return host

    def test_local_session_scope_and_agent_call_participate_in_drain(self):
        host = self.host()
        with host.local_session_service("request", "request-id") as result:
            self.assertEqual(result, ("request", "request-id"))
            self.assertEqual(host.active, 1)
        self.assertEqual(host.local_agent_call("challenge", {"session": "fixture"}, "request-id"),
            {"value": {"session": "fixture"}, "request_id": "request-id"})
        self.assertEqual(host.active, 0)

    def test_url_proxies_resolve_only_during_request(self):
        with patch.object(gunicorn.policy_host, "local_session_service", return_value="scope") as sessions:
            self.assertEqual(gunicorn.local_session_factory("request", "request-id"), "scope")
            sessions.assert_called_once_with("request", "request-id")
        with patch.object(gunicorn.policy_host, "local_agent_call", return_value={"ok": True}) as agent:
            self.assertEqual(gunicorn.local_agent_runtime.challenge({}, "request-id"), {"ok": True})
            agent.assert_called_once_with("challenge", {}, "request-id")

    def test_enabled_routes_require_complete_native_runtime_before_redis(self):
        with self.assertRaisesRegex(ValueError, "native lifecycle/version adapters"):
            configure_policy(self.config(), directory_authorization=Mock(), local_edit_enabled=True)

        with self.assertRaisesRegex(ValueError, "native lifecycle/version adapters"):
            configure_policy(self.config(), directory_authorization=Mock(), local_edit_enabled=True,
                resource_secret=b"s" * 32, lifecycle_reader=Mock(),
                local_edit_instance="https://cloudfile.invalid/", local_edit_version_reader="invalid")


if __name__ == "__main__":
    unittest.main()
