"""Default presentation privacy for already-authorized audit facts.

Never resolves a legacy operator/email into a business identity. Stored facts
remain unchanged; this function is not an authorization decision.
"""
from ..common.validation import identifier
from ..common.errors import ContractError
from .query import AuditReader


def redact_event(redact, actor, event):
    """Apply the same fact-preserving presentation contract to JSON and CSV."""
    try:
        value = redact(actor, dict(event))
        if not isinstance(value, dict) or not set(AuditReader.FIELDS) <= value.keys():
            raise ValueError()
        for field in ("id", "event_id", "schema_version", "occurred_at", "recorded_at",
                      "repo_id", "resource_uid", "source", "operation", "result"):
            if value[field] != event[field]:
                raise ValueError()
        if event["schema_version"] == 0 and any(
                value[field] is not None for field in ("actor_user_id", "actor_kind")):
            raise ValueError()
        return {field: value[field] for field in AuditReader.FIELDS}
    except Exception:
        raise ContractError("AUDIT_UNAVAILABLE", "Audit redaction is unavailable", 503) from None


def default_redact(actor, event):
    identifier(actor, maximum=225)
    result = dict(event)
    if type(result.get("schema_version")) is not int:
        raise ValueError("invalid audit schema")
    if result["schema_version"] == 0:
        if result.get("actor_user_id") is not None or result.get("actor_kind") is not None:
            raise ValueError("legacy audit identity cannot be inferred")
        result["operator"] = "[redacted]"
    elif result["schema_version"] == 1:
        subject = identifier(result.get("actor_user_id"), maximum=225)
        if result.get("actor_kind") not in ("user", "service"):
            raise ValueError("invalid audit actor kind")
        result["operator"] = subject
    else:
        raise ValueError("unsupported audit schema")
    # Delegation detail may contain a native login or external principal. Expose
    # only the recorded business actor by default, not an unclassified identity.
    result["delegator"] = None
    return result
