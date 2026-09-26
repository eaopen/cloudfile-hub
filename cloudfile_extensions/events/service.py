"""Audit domain service for authenticated HTTP adapters; no route registration.

Runtime must supply current native scope guards and deployment redaction. Actor
is authenticated input, never a request field. DTOs exclude internal job data.
"""

from datetime import datetime, timezone
import math
from functools import wraps
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields, utc_time
from ..resources.paths import normalize_path
from .query import AuditReader


def safe_errors(method):
    @wraps(method)
    def invoke(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ContractError:
            raise
        except Exception:
            raise ContractError("AUDIT_UNAVAILABLE", "Audit service is unavailable", 503) from None
    return invoke


class AuditService:
    def __init__(self, reader, jobs, *, export_guard, redact):
        if not callable(export_guard) or not callable(redact):
            raise ValueError("native export scope guard and redaction are required")
        self.reader, self.jobs, self.guard, self.redact = reader, jobs, export_guard, redact

    @staticmethod
    def _filters(value):
        object_fields(value, ("repo_id", "start", "end"),
                      ("actor_user_id", "action", "result", "path", "resource_uid"))
        result = dict(value)
        try:
            result["repo_id"] = str(UUID(value["repo_id"]))
            if "resource_uid" in value:
                result["resource_uid"] = str(UUID(value["resource_uid"]))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid audit resource identity", 400) from None
        start, end = utc_time(value["start"]), utc_time(value["end"])
        if not 0 < (end - start).total_seconds() <= 31 * 86400:
            raise ContractError("INVALID_REQUEST", "Audit window must be at most 31 days", 400)
        for field in ("actor_user_id", "action", "result"):
            if field in value:
                identifier(value[field])
        if "path" in value:
            result["path"] = normalize_path(value["path"], "dir")
        return result

    @safe_errors
    def events(self, *, actor, filters, limit=100, cursor=None):
        identifier(actor)
        page = self.reader.list(actor=actor, **self._filters(filters), limit=limit, cursor=cursor)
        items = []
        for event in page["items"]:
            redacted = self.redact(actor, dict(event))
            if not isinstance(redacted, dict) or not set(AuditReader.FIELDS) <= redacted.keys():
                raise ContractError("AUDIT_UNAVAILABLE", "Audit redaction is unavailable", 503)
            for field in ("id", "event_id", "schema_version", "occurred_at", "recorded_at", "repo_id", "resource_uid", "source", "operation", "result"):
                if redacted[field] != event[field]:
                    raise ContractError("AUDIT_UNAVAILABLE", "Audit redaction changed a fact identity", 503)
            if event["schema_version"] == 0 and any(redacted[field] is not None for field in ("actor_user_id", "actor_kind")):
                raise ContractError("AUDIT_UNAVAILABLE", "Legacy audit identity cannot be inferred", 503)
            # Deployment redaction cannot append arbitrary internal fields.
            items.append({field: redacted[field] for field in AuditReader.FIELDS})
        return {"items": items, "next_cursor": page["next_cursor"]}

    @safe_errors
    def create_export(self, *, actor, request, idempotency_key):
        identifier(actor)
        filters = self._filters(request)
        repo = filters.pop("repo_id")
        # Guard must protect actual submission's native authorization, not just
        # perform an earlier boolean check. Test guards are not runtime proof.
        with self.guard(actor, repo):
            job_id, created = self.jobs.submit(actor=actor, actor_kind="user", kind="audit.export",
                scope={"type": "repo", "provider": "cloudfile", "external_id": repo},
                request=filters, idempotency_key=idempotency_key)
            return self._dto(self.jobs.get(job_id)), created

    def _own_job(self, job_id, actor):
        identifier(actor)
        try:
            job_id = str(UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid audit export identity", 400) from None
        job = self.jobs.get(job_id)
        if (job["kind"] != "audit.export" or job["actor_kind"] != "user" or job["actor"] != actor or
                job["scope"].get("type") != "repo" or job["scope"].get("provider") != "cloudfile"):
            raise ContractError("NOT_FOUND", "Audit export is not available", 404)
        return job

    @safe_errors
    def export_status(self, job_id, *, actor):
        job = self._own_job(job_id, actor)
        with self.guard(actor, job["scope"]["external_id"]):
            return self._dto(self.jobs.get(job["job_id"]))

    @safe_errors
    def cancel_export(self, job_id, *, actor):
        job = self._own_job(job_id, actor)
        with self.guard(actor, job["scope"]["external_id"]):
            return self._dto(self.jobs.cancel(job["job_id"], actor=actor, actor_kind="user"))

    @staticmethod
    def _dto(job):
        base = "/api/v2.1/cloudfile/extensions/audit/v1/exports/" + job["job_id"] + "/"
        expires = None
        if job["status"] == "succeeded":
            try:
                metadata = job["checkpoint"]
                expected = "audit-export:" + job["job_id"] + "." + str(job["lease_epoch"]) + ".csv"
                if (metadata["result_ref"] != expected or job["result_ref"] != expected or
                        type(metadata["expires_at"]) not in (int, float) or not math.isfinite(metadata["expires_at"])):
                    raise ValueError()
                expires = datetime.fromtimestamp(metadata["expires_at"], timezone.utc).isoformat().replace("+00:00", "Z")
            except (KeyError, ValueError, TypeError, OverflowError, OSError):
                raise ContractError("EXPORT_UNAVAILABLE", "Audit export metadata is unavailable", 503) from None
        return {"job_id": job["job_id"], "repo_id": job["scope"]["external_id"], "status": job["status"],
                "step": job["step"], "status_url": base, "result_url": base + "result/" if expires else None,
                "expires_at": expires, "error_code": job["error_code"] if job["status"] == "failed" else None}
