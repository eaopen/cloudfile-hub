"""Same-cursor lease persistence, never an authorized API or native grant."""
import hashlib
import hmac
import re
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import identifier


class LockLeaseStore:
    """Caller owns real authorization/lifecycle guard and SQL commit.

    Trusted service supplies the secret token; only its digest is persisted.
    Released rows must remain forever to preserve monotonic fencing.
    """
    @staticmethod
    def _key(sql, uid, repo):
        if str(UUID(uid)) != uid or str(UUID(repo)) != repo:
            raise ValueError("canonical resource/library required")
        sql.execute("SAVEPOINT cf_lock_transaction")
        sql.execute("RELEASE SAVEPOINT cf_lock_transaction")

    @staticmethod
    def _holder(actor, holder, token, seconds):
        identifier(actor, maximum=225)
        identifier(holder, maximum=128)
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("cryptographic lease token required")
        if type(seconds) is not int or not 60 <= seconds <= 1800:
            raise ValueError("lease duration must be 60..1800 seconds")
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    @staticmethod
    def _load(sql, uid, repo):
        sql.execute("SELECT repo_id,fencing,owner_user_id,holder_id,token_digest,base_version,expires_at,IF(expires_at>UTC_TIMESTAMP(6),1,0) FROM cf_lock_lease WHERE resource_uid=%s FOR UPDATE", (uid,))
        row = sql.fetchone()
        if row is None:
            return None
        if (len(row) != 8 or row[0] != repo or type(row[1]) is not int or not 0 <= row[1] <= 2 ** 64 - 1 or
                type(row[7]) is not int or row[7] not in (0, 1)):
            raise ContractError("LOCK_STATE_PENDING", "Invalid lease identity", 503)
        if not all(value is None for value in row[2:7]):
            if (any(value is None for value in row[2:7]) or row[1] == 0 or
                    not isinstance(row[4], str) or not re.fullmatch(r"[0-9a-f]{64}", row[4]) or
                    not isinstance(row[5], str) or not re.fullmatch(r"[0-9a-f]{40}", row[5])):
                raise ContractError("LOCK_STATE_PENDING", "Invalid lease state", 503)
            identifier(row[2], maximum=225)
            identifier(row[3], maximum=128)
        return row

    @staticmethod
    def _bump(sql, repo):
        sql.execute("INSERT INTO cf_lock_repo_revision(repo_id,revision) VALUES(%s,1) ON DUPLICATE KEY UPDATE revision=revision+1", (repo,))

    @staticmethod
    def _result(row):
        return dict(fencing=str(row[1]), active=row[7] == 1, owner_user_id=row[2] if row[7] else None,
            holder_id=row[3] if row[7] else None, base_version=row[5] if row[7] else None,
            expires_at=row[6].isoformat(timespec="microseconds") + "Z" if row[7] else None)

    def acquire(self, sql, *, resource_uid, repo_id, actor, holder, token, base_version, seconds=600):
        self._key(sql, resource_uid, repo_id)
        digest = self._holder(actor, holder, token, seconds)
        if not isinstance(base_version, str) or not re.fullmatch(r"[0-9a-f]{40}", base_version):
            raise ValueError("actual CE content version required")
        sql.execute("INSERT INTO cf_lock_lease(resource_uid,repo_id,fencing) VALUES(%s,%s,0) ON DUPLICATE KEY UPDATE resource_uid=resource_uid", (resource_uid, repo_id))
        row = self._load(sql, resource_uid, repo_id)
        if row[7]:
            if row[2] == actor and row[3] == holder and hmac.compare_digest(row[4], digest) and row[5] == base_version:
                return self._result(row)  # Acquisition replay never renews.
            raise ContractError("RESOURCE_LOCKED", "Resource has an active lease", 423)
        if row[1] == 2 ** 64 - 1:
            raise ContractError("LOCK_STATE_PENDING", "Lease fencing exhausted", 503)
        sql.execute("UPDATE cf_lock_lease SET fencing=fencing+1,owner_user_id=%s,holder_id=%s,token_digest=%s,base_version=%s,expires_at=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6)) WHERE resource_uid=%s AND fencing=%s", (actor, holder, digest, base_version, seconds, resource_uid, row[1]))
        if sql.rowcount != 1:
            raise ContractError("LOCK_CONFLICT", "Lease changed", 409)
        self._bump(sql, repo_id)
        return self._result(self._load(sql, resource_uid, repo_id))

    def change(self, sql, *, resource_uid, repo_id, actor, holder, token, fencing, release=False, seconds=600):
        self._key(sql, resource_uid, repo_id)
        digest = self._holder(actor, holder, token, seconds)
        if type(fencing) is not int or not 1 <= fencing <= 2 ** 64 - 1 or type(release) is not bool:
            raise ValueError("exact fencing/action required")
        row = self._load(sql, resource_uid, repo_id)
        if (row is None or not row[7] or row[1] != fencing or row[2] != actor or row[3] != holder or
                not hmac.compare_digest(row[4], digest)):
            raise ContractError("LOCK_CONFLICT", "Lease expired or ownership changed", 409)
        if release:
            sql.execute("UPDATE cf_lock_lease SET owner_user_id=NULL,holder_id=NULL,token_digest=NULL,base_version=NULL,expires_at=NULL WHERE resource_uid=%s AND fencing=%s AND expires_at>UTC_TIMESTAMP(6)", (resource_uid, fencing))
        else:
            sql.execute("UPDATE cf_lock_lease SET expires_at=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6)) WHERE resource_uid=%s AND fencing=%s AND expires_at>UTC_TIMESTAMP(6)", (seconds, resource_uid, fencing))
        if sql.rowcount != 1:
            raise ContractError("LOCK_CONFLICT", "Lease expired before mutation", 409)
        self._bump(sql, repo_id)
        return self._result(self._load(sql, resource_uid, repo_id))

    def status(self, sql, *, resource_uid, repo_id):
        self._key(sql, resource_uid, repo_id)
        row = self._load(sql, resource_uid, repo_id)
        return self._result(row) if row is not None else dict(fencing="0", active=False,
            owner_user_id=None, holder_id=None, base_version=None, expires_at=None)

    def force_release(self, sql, *, resource_uid, repo_id, fencing):
        self._key(sql, resource_uid, repo_id)
        if type(fencing) is not int or not 1 <= fencing < 2 ** 64 - 1:
            raise ValueError("bounded management fencing required")
        row = self._load(sql, resource_uid, repo_id)
        if row is None or row[1] != fencing or row[4] is None:
            raise ContractError("LOCK_CONFLICT", "Lease changed before management recovery", 409)
        # Invalidate the administrative target even if already expired. Retain
        # its UID and strictly increase fencing; never delete/reset the row.
        sql.execute("UPDATE cf_lock_lease SET fencing=fencing+1,owner_user_id=NULL,holder_id=NULL,token_digest=NULL,base_version=NULL,expires_at=NULL WHERE resource_uid=%s AND fencing=%s", (resource_uid, fencing))
        if sql.rowcount != 1:
            raise ContractError("LOCK_CONFLICT", "Lease changed", 409)
        self._bump(sql, repo_id)
        return self._result(self._load(sql, resource_uid, repo_id))
