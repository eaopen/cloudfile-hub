"""Issuer orchestration only; native RPC/SQL integration remains unverified."""
import json
import sys
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cloudfile_extensions.identity.read_ticket import OIDCReadTicketIssuer
from cloudfile_extensions.identity.native_session import SESSION_REFERENCE_KEY
from cloudfile_extensions.common.errors import ContractError


class ReadTicketTests(unittest.TestCase):
    def setUp(self):
        self.issuer = object.__new__(OIDCReadTicketIssuer)
        self.issuer.preparation = Mock(actor="user-1")
        self.issuer.preparation.state.provider = "etech"
        self.issuer.preparation.state.username.return_value = "native-user"
        self.issuer.preparation.contexts.current.return_value = dict(context_epoch="a" * 32)
        self.in_guard = False

        @contextmanager
        def guard(request):
            self.in_guard = True
            try:
                yield
            finally:
                self.in_guard = False
        self.issuer.authority = SimpleNamespace(guard=guard)
        session = Mock(session_key="b" * 32)
        session.get.return_value = dict(scope_hash="c" * 64, subject_hash="d" * 64,
            sid_hash=None, authenticated_at=123)
        self.request = SimpleNamespace(session=session,
            user=SimpleNamespace(is_authenticated=True, username="native-user"))
        self.ref = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/file", kind="file")
        self.rpc = Mock()
        self.rpc.get_file_id_by_commit_and_path.return_value = "e" * 40
        self.token = "22222222-2222-2222-2222-222222222222"
        def issue(*arguments):
            self.assertFalse(self.in_guard)
            return self.token
        self.rpc.seafile_cloudfile_issue_read_ticket.side_effect = issue
        self.api = Mock()
        self.api.get_repo.return_value = SimpleNamespace(head_cmmt_id="f" * 40)
        self.native = SimpleNamespace(seafserv_threaded_rpc=self.rpc, seafile_api=self.api)

    def test_resolves_exact_commit_and_captures_server_session(self):
        with patch.dict(sys.modules, seaserv=self.native), patch(
                "cloudfile_extensions.identity.read_ticket.issue_native_ticket",
                self.rpc.seafile_cloudfile_issue_read_ticket):
            result = self.issuer.issue(self.request, self.ref)
        self.assertEqual(result, dict(ticket=self.token, expires_in=60))
        self.rpc.get_file_id_by_commit_and_path.assert_called_once_with(
            self.ref["repo_id"], "f" * 40, "/file")
        args = self.rpc.seafile_cloudfile_issue_read_ticket.call_args.args
        conditions = json.loads(args[-1])
        self.assertEqual(conditions["oidc_session"]["session_key"], "b" * 32)
        self.assertEqual(conditions["context"]["userId"], "user-1")
        self.request.session.get.assert_called_with(SESSION_REFERENCE_KEY)

    def test_missing_file_never_issues_ticket(self):
        self.rpc.get_file_id_by_commit_and_path.return_value = None
        with patch.dict(sys.modules, seaserv=self.native), patch(
                "cloudfile_extensions.identity.read_ticket.issue_native_ticket",
                self.rpc.seafile_cloudfile_issue_read_ticket), self.assertRaises(ContractError):
            self.issuer.issue(self.request, self.ref)
        self.rpc.seafile_cloudfile_issue_read_ticket.assert_not_called()
