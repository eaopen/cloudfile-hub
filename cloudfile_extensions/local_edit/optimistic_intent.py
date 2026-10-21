"""Mode-neutral publication receipt contract; optimistic has no Guard.

Existing cf_commit_intent remains untouched and authoritative for checkout.
An optimistic intent must be prepared before any bytes are submitted. Its
native published transition is committed in the SAME Branch transaction.
"""
import re
from ..common.errors import ContractError
from ..common.validation import object_fields

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")


class OptimisticIntentStore:
    @staticmethod
    def prepare(sql, value, *, session, device, repo):
        object_fields(value, ("intent_id", "base_file_id", "content_digest", "snapshot_size"))
        if (not all(isinstance(item, str) and UUID.fullmatch(item)
                    for item in (value["intent_id"],session,device,repo)) or
                not isinstance(value["base_file_id"], str) or
                not SHA40.fullmatch(value["base_file_id"]) or
                not isinstance(value["content_digest"], str) or
                not SHA64.fullmatch(value["content_digest"]) or
                type(value["snapshot_size"]) is not int or
                not 0 <= value["snapshot_size"] <= 128 * 1024 * 1024):
            raise ValueError("Bounded optimistic original upload intent required")
        # Do not update an existing Intent on duplicate: the original snapshot
        # and its established file identity are immutable even across retries.
        sql.execute("INSERT INTO cf_optimistic_upload_intent"
            "(intent_id,session_id,device_id,repo_id,base_file_id,"
            "content_digest,snapshot_size,state,created_at)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,'prepared',UTC_TIMESTAMP(6))"
            " ON DUPLICATE KEY UPDATE intent_id=intent_id",
            (value["intent_id"],session,device,repo,value["base_file_id"],
             value["content_digest"],value["snapshot_size"]))
        result=OptimisticIntentStore.receipt(sql, value["intent_id"],
                session=session,device=device,repo=repo)
        if (result["base_file_id"]!=value["base_file_id"] or
                result["content_digest"]!=value["content_digest"] or
                result["snapshot_size"]!=value["snapshot_size"]):
            raise ContractError("EDIT_CONFLICT","Original optimistic intent is immutable",409)
        return result

    @staticmethod
    def receipt(sql, intent, *, session, device, repo=None):
        if (not UUID.fullmatch(intent) or not UUID.fullmatch(session) or
                not UUID.fullmatch(device)):
            raise ValueError("Canonical optimistic receipt key required")
        sql.execute("SELECT session_id,device_id,repo_id,base_file_id,"
            "content_digest,snapshot_size,state,result_file_id "
            "FROM cf_optimistic_upload_intent WHERE intent_id=%s FOR UPDATE",
            (intent,))
        row=sql.fetchone()
        if not row or row[0]!=session or row[1]!=device or (repo is not None and row[2]!=repo):
            return dict(state="not-found",intent_id=intent)
        if row[6] not in ("prepared","published") or (row[6]=="published" and
             (not isinstance(row[7],str) or not SHA40.fullmatch(row[7]))):
            raise ContractError("EDIT_CONFLICT","Original optimistic intent needs reconciliation",409)
        return dict(intent_id=intent, state=row[6],base_file_id=row[3],
            content_digest=row[4],snapshot_size=int(row[5]),
            result_file_id=row[7])
