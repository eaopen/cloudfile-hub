"""Device-only bounded byte staging into the existing native Branch publisher."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import time
from uuid import uuid4

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from ..common.errors import ContractError, invalid
from .agent_runtime import AgentClaimRuntime
from .commit_contract import MAX_MANUAL_BYTES


def stage(request, output, *, size, digest):
    from .shared_staging import stage_chunks
    def raw():
        remaining=size
        while remaining:
            part=request.read(min(65536,remaining))
            if not part:
                raise invalid("Incomplete upload")
            remaining-=len(part)
            yield part
        if request.read(1):
            raise invalid("Upload stream exceeded declared size")
    return stage_chunks(output,raw(),expected_size=size,
                        max_bytes=MAX_MANUAL_BYTES,digest=digest,
                        protect_snapshot=True)


@method_decorator(csrf_exempt, name="dispatch")
class AgentUploadView(View):
    runtime = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Upload requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure upload required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or "Cookie" in request.headers or
                    "Content-Encoding" in request.headers or "Transfer-Encoding" in request.headers):
                raise invalid("Upload requires only a device bearer and raw bytes")
            if request.headers.get("Content-Type") != "application/octet-stream":
                raise ContractError("UNSUPPORTED_MEDIA_TYPE", "Raw snapshot required", 415)
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or not isinstance(self.runtime, AgentClaimRuntime):
                raise ContractError("AUTHENTICATION_REQUIRED", "Device upload credential required", 401)
            grant = self.runtime.upload_grant(auth[7:], request_id)
            size = grant["snapshot_size"]
            edit = grant["condition"]["editing"]
            if (type(size) is not int or not 0 <= size <= MAX_MANUAL_BYTES or
                    request.headers.get("Content-Length") != str(size) or
                    request.headers.get("Idempotency-Key") != edit["intent_id"]):
                raise invalid("Upload does not match the captured intent")
            data_dir = os.environ.get("SEAFILE_DATA_DIR", "")
            if not os.path.isabs(data_dir):
                raise ContractError("EDIT_UNAVAILABLE", "Native staging unavailable", 503)
            with tempfile.NamedTemporaryFile(dir=Path(data_dir) / "httptemp", prefix="cf-device-edit-") as output:
                stage(request, output, size=size, digest=grant["content_digest"])
                result = self.runtime.upload_receipt(grant, request_id)
                if result["state"] != "published":
                    if result["state"] != "prepared":
                        raise ContractError("EDIT_CONFLICT", "Original intent is not prepared", 409)
                    from ..identity.ticket_transport import _call
                    condition = grant["condition"]
                    repo = edit["repo_id"]
                    current = _call("seafile_get_repo", (repo,), time.monotonic() + 5)
                    heads = [name for name in ("head_cmmt_id", "head-cmmt-id") if name in current]
                    if len(heads) != 1:
                        raise ContractError("EDIT_UNAVAILABLE", "Native head unavailable", 503)
                    condition["head_id"] = current[heads[0]]
                    parent, _, filename = condition["path"].rpartition("/")
                    try:
                        _call("seafile_cloudfile_publish_edit", (repo, output.name, parent or "/", filename,
                            grant["native_user"], json.dumps(condition, separators=(",", ":"))),
                            time.monotonic() + 180)
                    except Exception:
                        # Native may have committed before the RPC reply was lost.
                        pass
                    result = self.runtime.upload_receipt(grant, request_id)
                if (result["state"] != "published" or result.get("content_digest") != grant["content_digest"] or
                        result.get("expected_file_id") != edit["base_file_id"] or
                        result.get("action") != grant["action"]):
                    raise ContractError("PUBLICATION_UNCONFIRMED", "Recover the original intent", 503)
            response = JsonResponse(dict(intent=result))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            response = JsonResponse(invalid("Invalid upload").response(request_id), status=400)
        except Exception:
            error = ContractError("EDIT_UNAVAILABLE", "Device upload unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Request-ID"] = request_id
        return response
