"""Actual SQL single-use consumption; no resource/HTTP/native publication proof."""
import hashlib
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.session_store import LocalSessionStore, snapshot_json
from cloudfile_extensions.tests.test_device_store import DeviceStoreTests


class LocalSessionStoreTests(DeviceStoreTests):
    def test_device_cancel_can_stop_expired_session_and_is_proof_atomic(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                owner = {key: args[key] for key in ("provider", "actor", "device_id", "session_id", "instance")}
                sql.execute("UPDATE cf_edit_session SET expires_at=1 WHERE session_id=%s", (issued.session_id,))
                challenge = sessions.cancel_challenge(sql, **owner)
                sql.execute("SAVEPOINT cancel_effect")
                first, changed = sessions.cancel_with_proof(sql, **owner, challenge=challenge, signature=self.sign(challenge))
                self.assertTrue(changed)
                self.assertEqual(first["state"], "cancelled")
                sql.execute("ROLLBACK TO SAVEPOINT cancel_effect")
                repeated, changed = sessions.cancel_with_proof(sql, **owner, challenge=challenge, signature=self.sign(challenge))
                self.assertTrue(changed)
                self.assertEqual(first, repeated)
                with self.assertRaises(ContractError):
                    sessions.cancel_with_proof(sql, **owner, challenge=challenge, signature=self.sign(challenge))
                fresh = sessions.cancel_challenge(sql, **owner)
                result, changed = sessions.cancel_with_proof(sql, **owner, challenge=fresh, signature=self.sign(fresh))
                self.assertFalse(changed)
                self.assertEqual(result, first)
        finally:
            self.connection.rollback()

    def test_device_cancel_rejects_stale_state_and_unknown_publish(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                owner = {key: args[key] for key in ("provider", "actor", "device_id", "session_id", "instance")}
                challenge = sessions.cancel_challenge(sql, **owner)
                sql.execute("SAVEPOINT before_change")
                for state in ("committing", "completed", "active"):
                    sql.execute("UPDATE cf_edit_session SET state=%s WHERE session_id=%s", (state, issued.session_id))
                    with self.assertRaises(ContractError):
                        sessions.cancel_with_proof(sql, **owner, challenge=challenge, signature=self.sign(challenge))
                    sql.execute("ROLLBACK TO SAVEPOINT before_change")
        finally:
            self.connection.rollback()

    def test_renew_preserves_state_and_invalidates_old_read_proof(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                sql.execute("SELECT expires_at FROM cf_edit_session WHERE session_id=%s", (issued.session_id,))
                previous_expiry = sql.fetchone()[0]
                read = sessions.read_challenge(sql, **args)
                renewal = sessions.renew_challenge(sql, **args)
                result = sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
                self.assertEqual(result["state"], "claimed")
                self.assertEqual(result["revision"], "3")
                self.assertGreaterEqual(result["expires_at"], previous_expiry)
                with self.assertRaises(ContractError):
                    sessions.authorize_read(sql, **args, challenge=read, signature=self.sign(read))
                with self.assertRaises(ContractError):
                    sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
                fresh = sessions.read_challenge(sql, **args)
                self.assertEqual(sessions.authorize_read(sql, **args, challenge=fresh,
                    signature=self.sign(fresh))["session_revision"], "3")
        finally:
            self.connection.rollback()

    def test_renew_cannot_revive_terminal_or_unknown_publish(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                renewal = sessions.renew_challenge(sql, **args)
                sql.execute("SAVEPOINT before_stop")
                for state in ("created", "cancelled", "expired", "committing", "completed", "failed", "conflicted"):
                    sql.execute("UPDATE cf_edit_session SET state=%s WHERE session_id=%s", (state, issued.session_id))
                    with self.assertRaises(ContractError):
                        sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
                    sql.execute("ROLLBACK TO SAVEPOINT before_stop")
                sql.execute("UPDATE cf_edit_session SET expires_at=1 WHERE session_id=%s", (issued.session_id,))
                with self.assertRaises(ContractError):
                    sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
        finally:
            self.connection.rollback()

    def test_renew_is_atomic_with_proof_consumption(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                _, args = self.claimed(sql, sessions)
                renewal = sessions.renew_challenge(sql, **args)
                sql.execute("SAVEPOINT renewal_effect")
                result = sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
                sql.execute("ROLLBACK TO SAVEPOINT renewal_effect")
                retried = sessions.renew(sql, **args, challenge=renewal, signature=self.sign(renewal))
                self.assertEqual(retried["revision"], result["revision"])
                self.assertEqual(retried["state"], "claimed")
        finally:
            self.connection.rollback()

    def claimed(self, sql, sessions):
        self.active(sql)
        issued = sessions.create(sql, **self.owner, snapshot=self.snapshot())
        args = dict(**self.owner, session_id=issued.session_id, ticket=issued.ticket,
            current_snapshot=self.snapshot(), instance="https://cloudfile.invalid")
        challenge = sessions.challenge(sql, **args)
        sessions.claim(sql, **args, challenge=challenge, signature=self.sign(challenge))
        del args["ticket"]
        return issued, args

    def test_read_consumes_once_without_activity_extension(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                sql.execute("SELECT revision,expires_at FROM cf_edit_session WHERE session_id=%s", (issued.session_id,))
                before = sql.fetchone()
                challenge = sessions.read_challenge(sql, **args)
                result = sessions.authorize_read(sql, **args, challenge=challenge, signature=self.sign(challenge))
                self.assertEqual(result, dict(session_id=issued.session_id, device_id=self.device_id,
                    device_revision="2", session_revision="2"))
                sql.execute("SELECT revision,expires_at FROM cf_edit_session WHERE session_id=%s", (issued.session_id,))
                self.assertEqual(sql.fetchone(), before)
                with self.assertRaises(ContractError):
                    sessions.authorize_read(sql, **args, challenge=challenge, signature=self.sign(challenge))
        finally:
            self.connection.rollback()

    def test_read_rejects_cancel_revoke_and_expiry_before_consumption(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                issued, args = self.claimed(sql, sessions)
                challenge = sessions.read_challenge(sql, **args)
                sql.execute("SAVEPOINT read_boundary")
                mutations = [
                    ("UPDATE cf_edit_session SET state='cancelled',revision=revision+1 WHERE session_id=%s", (issued.session_id,)),
                    ("UPDATE cf_local_device SET state='revoked',revision=revision+1 WHERE device_id=%s", (self.device_id,)),
                    ("UPDATE cf_edit_session SET expires_at=1 WHERE session_id=%s", (issued.session_id,)),
                    ("UPDATE cf_edit_session SET revision=revision+1 WHERE session_id=%s", (issued.session_id,))]
                for statement, parameters in mutations:
                    sql.execute(statement, parameters)
                    with self.assertRaises(ContractError):
                        sessions.authorize_read(sql, **args, challenge=challenge, signature=self.sign(challenge))
                    sql.execute("ROLLBACK TO SAVEPOINT read_boundary")
                    sql.execute("SELECT consumed_at FROM cf_local_device_challenge WHERE nonce_digest=%s",
                        (hashlib.sha256(challenge.nonce.encode("ascii")).hexdigest(),))
                    self.assertIsNone(sql.fetchone()[0])
        finally:
            self.connection.rollback()

    def test_read_current_snapshot_change_keeps_nonce_unused(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                _, args = self.claimed(sql, sessions)
                challenge = sessions.read_challenge(sql, **args)
                for key, replacement in (("base_version", "b" * 40), ("local_open_type", "UG12"),
                        ("lifecycle_ref", "new-life"), ("resource_revision", "new-revision")):
                    changed = {**args, "current_snapshot": {**self.snapshot(), key: replacement}}
                    with self.assertRaises(ContractError):
                        sessions.authorize_read(sql, **changed, challenge=challenge, signature=self.sign(challenge))
                self.assertEqual(sessions.authorize_read(sql, **args, challenge=challenge,
                    signature=self.sign(challenge))["session_revision"], "2")
        finally:
            self.connection.rollback()

    def test_read_proof_consumption_rolls_back_with_effect_transaction(self):
        sessions = LocalSessionStore()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                _, args = self.claimed(sql, sessions)
                challenge = sessions.read_challenge(sql, **args)
                sql.execute("SAVEPOINT before_read_effect")
                expected = sessions.authorize_read(sql, **args, challenge=challenge, signature=self.sign(challenge))
                sql.execute("ROLLBACK TO SAVEPOINT before_read_effect")
                self.assertEqual(sessions.authorize_read(sql, **args, challenge=challenge,
                    signature=self.sign(challenge)), expected)
        finally:
            self.connection.rollback()

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
