"""Device-authorized CDC block plan/stage/publish endpoints.

Every request has an independently refreshed device-signed, 60-second grant
issued by commit-upload-authorize. There is no browser cookie or repo-wide
upload token. Raw block stage is pathless. Only the native guarded Branch
transaction can finalize an Intent and advertise a published receipt.
"""
import json
import os
from pathlib import Path
import tempfile
import time
from uuid import uuid4

from django.conf import settings
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from ..common.errors import ContractError, invalid
from ..events.outbox import Outbox
from ..identity.ticket_transport import _call
from .agent_runtime import AgentClaimRuntime
from .block_contract import BlockPlanStore, MAX_BLOCK, MAX_FILE


def _read_json(request, max_bytes=65536):
    if request.headers.get("Content-Type") != "application/json":
        raise invalid("Only exact CDC plan JSON accepted")
    raw = request.read(max_bytes + 1)
    if not 0 < len(raw) <= max_bytes or request.read(1):
        raise invalid("Bounded CDC plan JSON required")
    from ..migration.native_status import _object
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, UnicodeError):
        raise invalid("Canonical CDC plan JSON required") from None


def _read_blocks(runtime, grant, request_id, *, new=None):
    with runtime.resources.connection() as connection:
        Outbox(connection)._require_idle()
        connection.begin()
        try:
            with connection.cursor() as sql:
                if new is None:
                    value, ordered, sizes = BlockPlanStore().load(sql, grant)
                else:
                    ordered, sizes = BlockPlanStore().create(sql, grant, new)
                    value = new
            connection.commit()
            return value, ordered, sizes
        finally:
            connection.rollback()


def _native_repo(repo):
    current = _call("seafile_get_repo", (repo,), time.monotonic() + 5)
    if (not isinstance(current, dict) or current.get("version") != 1 or
            current.get("encrypted") not in (False, 0) or
            current.get("is_virtual", False) not in (False, 0) or
            current.get("status", 0) != 0):
        raise ContractError("EDIT_UNAVAILABLE",
                            "CDC requires a writable unencrypted v1 library", 503)
    from .native_publish import native_head
    return native_head(current)


@method_decorator(csrf_exempt, name="dispatch")
class AgentBlockView(View):
    runtime = None
    operation = "plan"
    optimistic = False
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "CDC requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure device CDC required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or
                    "Cookie" in request.headers or "Transfer-Encoding" in request.headers or
                    "Content-Encoding" in request.headers or
                    not isinstance(self.runtime, AgentClaimRuntime) or
                    type(getattr(settings, "CLOUDFILE_AGENT2_CDC_ENABLED", False)) is not bool or
                    not getattr(settings, "CLOUDFILE_AGENT2_CDC_ENABLED", False)):
                raise ContractError("EDIT_UNAVAILABLE", "Guarded CDC unavailable", 503)
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise ContractError("AUTHENTICATION_REQUIRED", "Signed device CDC grant required", 401)
            grant = (self.runtime.optimistic_upload_grant(auth[7:], request_id)
                     if self.optimistic else self.runtime.upload_grant(auth[7:], request_id))
            condition=grant["condition"]
            edit=(dict(intent_id=condition["agent_upload"]["intent_id"],
                repo_id=grant["repo_id"],
                base_file_id=condition["expected_file_id"])
                if self.optimistic else condition["editing"])
            get_receipt=(self.runtime.optimistic_upload_receipt
                if self.optimistic else self.runtime.upload_receipt)
            if request.headers.get("Idempotency-Key") != edit["intent_id"]:
                raise invalid("Original CommitIntent required")
            if type(grant["snapshot_size"]) is not int or not 1 <= grant["snapshot_size"] <= MAX_FILE:
                raise invalid("P0 CDC file limit exceeded")
            receipt = get_receipt(grant, request_id)
            if receipt["state"] == "published":
                result = dict(intent=receipt)
            elif receipt["state"] != "prepared":
                raise ContractError("EDIT_CONFLICT", "Device CommitIntent not prepared", 409)
            elif self.operation == "plan":
                body = _read_json(request)
                _native_repo(edit["repo_id"])
                value, ordered, _ = _read_blocks(self.runtime, grant, request_id, new=body)
                # Native check_repo_blocks_missing is pathless, but the broker
                # only accepts IDs in this device's signed current Intent.
                ids = list(dict.fromkeys(ordered))
                raw = _call("seafile_check_repo_blocks_missing",
                            (edit["repo_id"], json.dumps(ids, separators=(",", ":"))),
                            time.monotonic() + 20)
                try:
                    missing = json.loads(raw)
                    if (not isinstance(missing, list) or
                            len(missing) != len(set(missing)) or
                            not set(missing).issubset(ids)):
                        raise ValueError()
                except (ValueError, TypeError):
                    raise ContractError("EDIT_UNAVAILABLE",
                                        "Native missing-block response invalid", 503) from None
                result = dict(file_id=value["file_id"], missing=missing,
                              snapshot_size=value["size"], intent_id=edit["intent_id"])
            elif self.operation == "stage":
                if request.headers.get("Content-Type") != "application/octet-stream":
                    raise ContractError("UNSUPPORTED_MEDIA_TYPE", "Raw CDC bytes required", 415)
                value, ordered, sizes = _read_blocks(self.runtime, grant, request_id)
                block_id = request.headers.get("X-CloudFile-Block-ID", "")
                size = sizes.get(block_id)
                if (size is None or size > MAX_BLOCK or
                        request.headers.get("Content-Length") != str(size)):
                    raise invalid("Unplanned block or mismatched content length")
                data_dir = os.environ.get("SEAFILE_DATA_DIR", "")
                if not os.path.isabs(data_dir):
                    raise ContractError("EDIT_UNAVAILABLE", "Protected native storage unavailable", 503)
                from .shared_staging import stage_chunks
                def raw_blocks():
                    remaining = size
                    while remaining:
                        chunk = request.read(min(65536, remaining))
                        if not chunk:
                            raise invalid("Incomplete Seafile block stage")
                        remaining -= len(chunk)
                        yield chunk
                    if request.read(1):
                        raise invalid("Unexpected bytes after Seafile block")
                with tempfile.NamedTemporaryFile(dir=Path(data_dir) / "httptemp",
                                                 prefix="cf-device-cdc-") as tmp:
                    stage_chunks(tmp, raw_blocks(), expected_size=size,
                        max_bytes=MAX_BLOCK, digest=block_id, hash_algorithm="sha1")
                    _native_repo(edit["repo_id"])
                    outcome = _call("seafile_cloudfile_stage_raw_block",
                                (edit["repo_id"], block_id, tmp.name, grant["native_user"]),
                                time.monotonic() + 90)
                    if outcome != 0:
                        raise ContractError("EDIT_UNAVAILABLE", "Native CDC stage refused", 503)
                result = dict(staged=True, block_id=block_id, intent_id=edit["intent_id"])
            elif self.operation == "publish":
                if (request.headers.get("Content-Length") not in ("0", None) or
                        request.headers.get("X-CloudFile-Block-ID")):
                    raise invalid("CDC publication carries no new file bytes")
                value, ordered, sizes = _read_blocks(self.runtime, grant, request_id)
                current_head = _native_repo(edit["repo_id"])
                from .native_publish import cdc_native_publish
                try:
                    cdc_native_publish(call=_call, repo=edit["repo_id"],
                        ordered=ordered, size=value["size"],
                        user=grant["native_user"],condition=grant["condition"],
                        mode="optimistic" if self.optimistic else "exclusive",
                        head=current_head)
                except Exception:
                    # A real Branch update may have landed before reply loss.
                    pass
                receipt = get_receipt(grant, request_id)
                if (receipt["state"] != "published" or
                        receipt.get("result_file_id") != value["file_id"] or
                        receipt.get("content_digest") != value["sha256"] or
                        (receipt.get("base_file_id") if self.optimistic
                         else receipt.get("expected_file_id")) != edit["base_file_id"] or
                        (not self.optimistic and receipt.get("action") != grant["action"])):
                    raise ContractError("PUBLICATION_UNCONFIRMED", "Recover original Intent", 503)
                result = dict(intent=receipt)
            else:
                raise ContractError("METHOD_NOT_ALLOWED", "Unknown CDC operation", 405)
            response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            response = JsonResponse(invalid("Invalid guarded CDC request").response(request_id), status=400)
        except Exception:
            error = ContractError("EDIT_UNAVAILABLE", "CDC unavailable; original Intent retained", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Request-ID"] = request_id
        return response
