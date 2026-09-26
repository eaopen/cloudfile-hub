"""Actual SQL single-use consumption; no resource/HTTP/native publication proof."""
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.session_store import LocalSessionStore, snapshot_json
from cloudfile_extensions.tests.test_device_store import DeviceStoreTests


class LocalSessionStoreTests(DeviceStoreTests):
    def test_revoked_device_still_allows_own_stop_and_idempotent_cancel(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.active(sql)
                issued = sessions.create(sql, **self.owner, snapshot=self.snapshot())
                self.store.revoke(sql, **self.owner, expected_revision=2)
                args = dict(**self.owner, session_id=issued.session_id)
                status = sessions.status(sql, **args)
                self.assertFalse(status["device_available"])
                self.assertNotIn("snapshot", status)
                self.assertNotIn("resource", status)
                result, changed = sessions.cancel(sql, **args, expected_revision=1)
                self.assertTrue(changed)
                self.assertEqual(result["state"], "cancelled")
                self.assertEqual(sessions.cancel(sql, **args, expected_revision=1), (result, False))
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_stale_cancel_and_in_progress_publish_are_not_overwritten(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.active(sql)
                issued = sessions.create(sql, **self.owner, snapshot=self.snapshot())
                args = dict(**self.owner, session_id=issued.session_id)
                with self.assertRaises(ContractError):
                    sessions.cancel(sql, **args, expected_revision=2)
                sql.execute("UPDATE cf_edit_session SET state='committing' WHERE session_id=%s", (issued.session_id,))
                with self.assertRaises(ContractError):
                    sessions.cancel(sql, **args, expected_revision=1)
                self.assertEqual(sessions.status(sql, **args)["state"], "committing")
        finally:
            self.connection.rollback()

    def snapshot(self):
        return dict(resource=dict(repo_id="33333333-3333-4333-8333-333333333333", path="/drawing.prt", kind="file"),
            resource_uid="44444444-4444-4444-8444-444444444444", lifecycle_ref="native-lifecycle",
            base_version="a" * 40, resource_revision="opaque-revision", local_open_type="", mode="view", lease=None)

    def active(self, sql):
        self.create(sql)
        self.consume(sql, self.issue(sql))

    def test_actual_claim_consumes_ticket_and_device_challenge_once(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.active(sql)
                issued = sessions.create(sql, **self.owner, snapshot=self.snapshot())
                values = dict(**self.owner, session_id=issued.session_id, ticket=issued.ticket,
                    current_snapshot=self.snapshot(), instance="https://cloudfile.invalid")
                challenge = sessions.challenge(sql, **values)
                self.assertEqual(sessions.claim(sql, **values, challenge=challenge,
                    signature=self.sign(challenge))["state"], "claimed")
                with self.assertRaises(ContractError):
                    sessions.claim(sql, **values, challenge=challenge, signature=self.sign(challenge))
                sql.execute("SELECT ticket_digest FROM cf_edit_session WHERE session_id=%s", (issued.session_id,))
                self.assertNotEqual(sql.fetchone()[0], issued.ticket)
                self.assertNotIn(issued.ticket, repr(issued))
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_current_file_change_and_revoked_device_cannot_claim(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.active(sql)
                issued = sessions.create(sql, **self.owner, snapshot=self.snapshot())
                values = dict(**self.owner, session_id=issued.session_id, ticket=issued.ticket,
                    current_snapshot=self.snapshot(), instance="https://cloudfile.invalid")
                challenge = sessions.challenge(sql, **values)
                with self.assertRaises(ContractError):
                    sessions.claim(sql, **{**values, "current_snapshot": {**self.snapshot(), "base_version": "b" * 40}},
                        challenge=challenge, signature=self.sign(challenge))
                self.store.revoke(sql, **self.owner, expected_revision=2)
                with self.assertRaises(ContractError):
                    sessions.claim(sql, **values, challenge=challenge, signature=self.sign(challenge))
                sql.execute("SELECT state FROM cf_edit_session WHERE session_id=%s", (issued.session_id,))
                self.assertEqual(sql.fetchone()[0], "created")
        finally:
            self.connection.rollback()

    def test_snapshot_requires_explicit_exclusive_lease_and_single_file(self):
        with self.assertRaises((ValueError, ContractError)):
            snapshot_json({**self.snapshot(), "mode": "exclusive-edit"})
        with self.assertRaises((ValueError, ContractError)):
            snapshot_json({**self.snapshot(), "resource": {**self.snapshot()["resource"], "kind": "dir"}})
