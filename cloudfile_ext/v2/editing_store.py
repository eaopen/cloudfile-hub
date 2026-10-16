"""CF-EDIT SQL store. All mutators run inside the caller's seafile_db transaction.

The caller MUST authenticate the principal, check current CF-ACL write rights,
and use a trusted native File-ID reader. Never issue a publish/Checkin from
this module: the native Branch transaction alone owns that transition.

Lock order: Branch(master) -> cf_edit_guard -> cf_commit_intent.
"""
from secrets import token_hex
from uuid import uuid4

from .editing_contract import (
    CommitRequest, EditConflict, EditDenied, GuardProof, Principal,
    object_id, public_guard, reference, uuid, verify_proof,
)

GUARD_FIELDS = (
    "repo_id", "path_hash", "path", "guard_id", "generation", "credential_epoch",
    "mode", "owner_uid", "owner_native_user", "client_type", "client_id",
    "checkout_policy", "proof_digest", "base_file_id", "pending_intent",
    "lease_expires_at", "active",
)
INTENT_FIELDS = (
    "intent_id", "repo_id", "path_hash", "path", "guard_id", "generation",
    "credential_epoch", "actor_uid", "action", "expected_file_id",
    "staged_file_id", "content_digest", "request_digest", "state",
    "result_file_id", "result_commit_id",
)


class EditingStore:
    def __init__(self, native_file_id):
        """native_file_id(repo_id, path, locked_head) -> native 40-hex File ID."""
        if not callable(native_file_id):
            raise ValueError("native version reader required")
        self.native_file_id = native_file_id

    @staticmethod
    def lock_branch(cursor, repo_id):
        uuid(repo_id)
        cursor.execute(
            "SELECT commit_id FROM Branch WHERE name='master' AND repo_id=%s FOR UPDATE",
            (repo_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise EditDenied("native repository missing")
        return object_id(row[0])

    @staticmethod
    def lock_guard(cursor, repo_id, path):
        hashed = reference(repo_id, path)
        cursor.execute(
            "INSERT INTO cf_edit_guard(repo_id,path_hash,path) "
            "VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE repo_id=repo_id",
            (repo_id, hashed, path),
        )
        cursor.execute(
            "SELECT repo_id,path_hash,path,guard_id,generation,credential_epoch,"
            "mode,owner_uid,owner_native_user,client_type,client_id,"
            "checkout_policy,proof_digest,base_file_id,pending_intent,"
            "lease_expires_at,"
            "(guard_id IS NOT NULL AND (checkout_policy='persistent' OR "
            "lease_expires_at>UTC_TIMESTAMP(6))) AS active "
            "FROM cf_edit_guard WHERE repo_id=%s AND path_hash=%s FOR UPDATE",
            (repo_id, hashed),
        )
        row = cursor.fetchone()
        if row is None:
            raise EditDenied("guard state unavailable")
        result = dict(zip(GUARD_FIELDS, row))
        if result["path"] != path:
            raise EditDenied("resource path identity mismatch")
        return result

    @staticmethod
    def _receipt(cursor, intent_id, actor_uid):
        cursor.execute(
            "SELECT intent_id,repo_id,path_hash,path,guard_id,generation,"
            "credential_epoch,actor_uid,action,expected_file_id,"
            "staged_file_id,content_digest,request_digest,state,"
            "result_file_id,result_commit_id "
            "FROM cf_commit_intent WHERE intent_id=%s FOR UPDATE",
            (intent_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        receipt = dict(zip(INTENT_FIELDS, row))
        if receipt["actor_uid"] != actor_uid:
            raise EditDenied("intent belongs to a different principal")
        return receipt

    def read_receipt(self, cursor, intent_id, principal):
        uuid(intent_id)
        if not isinstance(principal, Principal):
            raise ValueError("trusted principal required")
        receipt = self._receipt(cursor, intent_id, principal.uid)
        if receipt is None:
            raise EditConflict("intent not found")
        return receipt

    def acquire(self, cursor, *, repo_id, path, principal, expected_file_id,
                mode="checkout", policy="renewable", lease_seconds=600,
                client_ref=None):
        """Use in authenticated, authorized seafile_db transaction."""
        if not isinstance(principal, Principal):
            raise ValueError("trusted principal required")
        if mode not in ("lock", "checkout") or policy not in ("renewable", "persistent"):
            raise ValueError("invalid reservation mode")
        if type(lease_seconds) is not int or not 60 <= lease_seconds <= 1800:
            raise ValueError("invalid lease duration")
        if client_ref is not None and (not isinstance(client_ref, str) or
                                       len(client_ref) > 225):
            raise ValueError("invalid external reference")
        expected_file_id = object_id(expected_file_id)
        head = self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        if row["guard_id"] is not None and (row["active"] or row["pending_intent"]):
            raise EditConflict("file is already checked out or locked")
        if object_id(self.native_file_id(repo_id, path, head)) != expected_file_id:
            raise EditConflict("native file version changed")
        if row["generation"] >= 2**64 - 1:
            raise EditDenied("guard fencing exhausted")
        token = token_hex(32)
        guard_id = str(uuid4())
        generation = row["generation"] + 1
        proof = GuardProof(guard_id, generation, 1, token)
        cursor.execute(
            "UPDATE cf_edit_guard SET guard_id=%s,generation=%s,credential_epoch=1,"
            "mode=%s,owner_uid=%s,owner_native_user=%s,client_type=%s,"
            "client_id=%s,client_ref=%s,checkout_policy=%s,proof_digest=%s,"
            "base_file_id=%s,pending_intent=NULL,"
            "lease_expires_at=IF(%s='renewable',"
            "TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6)),NULL),"
            "updated_at=UTC_TIMESTAMP(6) WHERE repo_id=%s AND path_hash=%s",
            (guard_id, generation, mode, principal.uid, principal.native_user,
             principal.client_type, principal.client_id, client_ref, policy,
             proof.token_digest, expected_file_id, policy, lease_seconds,
             repo_id, reference(repo_id, path)),
        )
        return proof

    def renew(self, cursor, *, repo_id, path, principal, proof, seconds=600):
        if type(seconds) is not int or not 60 <= seconds <= 1800:
            raise ValueError("invalid lease duration")
        self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        verify_proof(row, principal, proof)
        if row["checkout_policy"] != "renewable":
            raise EditConflict("persistent Checkout does not need a heartbeat")
        cursor.execute(
            "UPDATE cf_edit_guard SET lease_expires_at=TIMESTAMPADD("
            "SECOND,%s,UTC_TIMESTAMP(6)),updated_at=UTC_TIMESTAMP(6) "
            "WHERE repo_id=%s AND path_hash=%s AND guard_id=%s",
            (seconds, repo_id, reference(repo_id, path), proof.guard_id),
        )
        return proof.guard_id

    def resume(self, cursor, *, repo_id, path, principal, proof, expected_file_id):
        head = self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        verify_proof(row, principal, proof)
        if row["pending_intent"]:
            raise EditConflict("resolve previous prepared Intent first")
        if row["credential_epoch"] >= 2**64 - 1:
            raise EditDenied("credential counter exhausted")
        if (row["base_file_id"] != object_id(expected_file_id) or
                object_id(self.native_file_id(repo_id, path, head)) != expected_file_id):
            raise EditConflict("native file version changed")
        token = token_hex(32)
        new_proof = GuardProof(proof.guard_id, proof.generation,
                               proof.credential_epoch + 1, token)
        cursor.execute(
            "UPDATE cf_edit_guard SET credential_epoch=%s,proof_digest=%s,"
            "lease_expires_at=IF(checkout_policy='renewable',"
            "TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6)),NULL),"
            "updated_at=UTC_TIMESTAMP(6) WHERE repo_id=%s AND path_hash=%s",
            (new_proof.credential_epoch, new_proof.token_digest,
             repo_id, reference(repo_id, path)),
        )
        return new_proof

    def prepare(self, cursor, *, repo_id, path, principal, request, proof=None):
        if not isinstance(principal, Principal) or not isinstance(request, CommitRequest):
            raise ValueError("trusted principal and canonical request required")
        target_digest = reference(repo_id, path)
        body_digest = request.request_digest(repo_id, path, principal, proof)
        head = self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        prior = self._receipt(cursor, request.intent_id, principal.uid)
        if prior is not None:
            if prior["request_digest"] != body_digest:
                raise EditConflict("Intent ID reused for different content")
            return prior
        if (request.action == "optimistic"):
            # An unguarded write never inherits the writer's own lock.
            if row["guard_id"] is not None:
                raise EditConflict("file has a Checkout or lock reservation")
        else:
            if proof is None:
                raise EditDenied("Checkout credential required")
            verify_proof(row, principal, proof)
            if row["mode"] != "checkout":
                raise EditConflict("manual lock is not a Checkout")
            if row["pending_intent"]:
                raise EditConflict("previous prepared Intent must be resolved")
            if row["base_file_id"] != request.expected_file_id:
                raise EditConflict("Checkout baseline has changed")
        if object_id(self.native_file_id(repo_id, path, head)) != request.expected_file_id:
            raise EditConflict("native file version changed")
        cursor.execute(
            "INSERT INTO cf_commit_intent("
            "intent_id,repo_id,path_hash,path,guard_id,generation,credential_epoch,"
            "actor_uid,action,expected_file_id,staged_file_id,content_digest,"
            "request_digest,state,created_at,updated_at) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',"
            "UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",
            (request.intent_id, repo_id, target_digest, path,
             proof.guard_id if proof else None,
             proof.generation if proof else None,
             proof.credential_epoch if proof else None,
             principal.uid, request.action, request.expected_file_id,
             request.staged_file_id, request.content_digest, body_digest),
        )
        if proof:
            cursor.execute(
                "UPDATE cf_edit_guard SET pending_intent=%s,updated_at=UTC_TIMESTAMP(6) "
                "WHERE repo_id=%s AND path_hash=%s AND guard_id=%s",
                (request.intent_id, repo_id, target_digest, proof.guard_id),
            )
        return self._receipt(cursor, request.intent_id, principal.uid)

    @staticmethod
    def _cancel_locked(cursor, *, repo_id, path, row, receipt):
        """Atomically cancel ONLY an unpublished Intent under Branch -> Guard -> Intent locks.

        Publishing races serialize on Branch. A native publisher that won first
        leaves state='published', which cannot be cancelled or released here.
        """
        if (receipt is None or receipt["repo_id"] != repo_id or
                receipt["path_hash"] != reference(repo_id, path) or
                receipt["path"] != path or receipt["state"] != "prepared" or
                receipt["result_file_id"] is not None or
                receipt["result_commit_id"] is not None or
                (receipt["guard_id"] is not None and
                 (receipt["guard_id"] != row["guard_id"] or
                  row["pending_intent"] != receipt["intent_id"] or
                  receipt["generation"] != row["generation"] or
                  receipt["credential_epoch"] != row["credential_epoch"]))):
            raise EditConflict("prepared Intent cannot be safely cancelled")
        cursor.execute(
            "UPDATE cf_commit_intent SET state='cancelled',"
            "updated_at=UTC_TIMESTAMP(6) WHERE intent_id=%s AND state='prepared' "
            "AND result_file_id IS NULL AND result_commit_id IS NULL",
            (receipt["intent_id"],),
        )
        if cursor.rowcount != 1:
            raise EditConflict("Intent changed before cancellation")
        if receipt["guard_id"] is not None:
            cursor.execute(
                "UPDATE cf_edit_guard SET pending_intent=NULL,updated_at=UTC_TIMESTAMP(6)"
                " WHERE repo_id=%s AND path_hash=%s AND guard_id=%s "
                "AND pending_intent=%s",
                (repo_id, reference(repo_id, path), row["guard_id"],
                 receipt["intent_id"]),
            )
            if cursor.rowcount != 1:
                raise EditConflict("Guard changed before cancellation")

    def cancel_prepared(self, cursor, *, repo_id, path, principal,
                        intent_id, proof=None):
        # Current write authority remains mandatory for this call. An expired
        # proof can cancel but C native controlled publish cannot accept it.
        if not isinstance(principal, Principal):
            raise ValueError("trusted principal required")
        self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        receipt = self._receipt(cursor, uuid(intent_id), principal.uid)
        if receipt is None:
            raise EditConflict("Intent not found")
        if receipt["guard_id"] is not None:
            if proof is None:
                raise EditDenied("Checkout proof required")
            verify_proof(row, principal, proof, allow_expired=True)
        self._cancel_locked(cursor, repo_id=repo_id, path=path,
                            row=row, receipt=receipt)
        return intent_id

    def abandon(self, cursor, *, repo_id, path, principal, proof=None,
                management=False, reason=None):
        # Only a CURRENT management authority may set management=True; never
        # accept it from a request body. Both paths lock the actual Branch.
        if not isinstance(principal, Principal):
            raise ValueError("trusted principal required")
        if management and (not isinstance(reason, str) or not reason.strip()
                           or len(reason) > 512):
            raise ValueError("management reason required")
        self.lock_branch(cursor, repo_id)
        row = self.lock_guard(cursor, repo_id, path)
        if not row["guard_id"]:
            raise EditConflict("no Checkout or lock exists")
        if not management:
            if proof is None:
                raise EditDenied("proof required")
            verify_proof(row, principal, proof, allow_expired=True)
        if row["pending_intent"] is not None:
            # A manager or the current owner may safely cancel an unpublished
            # intent. This cannot discard a published receipt.
            receipt = self._receipt(cursor, row["pending_intent"], row["owner_uid"])
            self._cancel_locked(cursor, repo_id=repo_id, path=path,
                                row=row, receipt=receipt)
        cursor.execute(
            "UPDATE cf_edit_guard SET guard_id=NULL,mode=NULL,owner_uid=NULL,"
            "owner_native_user=NULL,client_type=NULL,client_id=NULL,client_ref=NULL,"
            "checkout_policy=NULL,proof_digest=NULL,base_file_id=NULL,"
            "pending_intent=NULL,lease_expires_at=NULL,credential_epoch=0,"
            "updated_at=UTC_TIMESTAMP(6) "
            "WHERE repo_id=%s AND path_hash=%s AND guard_id=%s",
            (repo_id, reference(repo_id, path), row["guard_id"]),
        )
        if cursor.rowcount != 1:
            raise EditConflict("Guard changed during release")
        return True
