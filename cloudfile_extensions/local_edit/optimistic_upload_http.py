"""One manually approved optimistic Agent file upload, without Checkout.

A device signature creates a short-lived encrypted ticket, bound to the
original optimistic-edit session, original file ID and captured file digest.
The actual native Branch CAS checks the current device/session, current
identity/ACL, path version and any managed lock. No cookie or Seafile update
token can authorize this endpoint. This initial mode is a one-shot upload:
an uncertain reply is NEVER interpreted as a durable published receipt.
"""
import os
from pathlib import Path
import re
import tempfile
from uuid import uuid4

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from ..common.errors import ContractError, invalid
from ..identity.ticket_transport import _call, NativeVersionConflict
from .agent_runtime import AgentClaimRuntime
from .upload_http import stage

_HEX40 = re.compile(r"^[a-f0-9]{40}$")
_UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


@method_decorator(csrf_exempt, name="dispatch")
class AgentOptimisticUploadView(View):
    runtime = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Manual optimistic upload requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Device TLS required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or
                    "Cookie" in request.headers or
                    "Content-Encoding" in request.headers or
                    "Transfer-Encoding" in request.headers):
                raise invalid("Only a signed device and raw file content are accepted")
            if request.headers.get("Content-Type") != "application/octet-stream":
                raise ContractError("UNSUPPORTED_MEDIA_TYPE", "Raw snapshot bytes required", 415)
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or not isinstance(self.runtime, AgentClaimRuntime):
                raise ContractError("AUTHENTICATION_REQUIRED", "Signed device grant required", 401)
            grant = self.runtime.optimistic_upload_grant(auth[7:], request_id)
            condition = grant["condition"]
            size, intent = grant["snapshot_size"], grant["intent_id"]
            if (type(size) is not int or not 0 <= size <= 128 * 1024 * 1024 or
                    not isinstance(intent, str) or not _UUID.fullmatch(intent) or
                    not isinstance(grant["content_digest"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", grant["content_digest"]) or
                    request.headers.get("Content-Length") != str(size) or
                    request.headers.get("Idempotency-Key") != intent or
                    not isinstance(grant["repo_id"], str) or
                    not isinstance(grant["native_user"], str) or
                    not isinstance(condition.get("expected_file_id"), str) or
                    not _HEX40.fullmatch(condition["expected_file_id"]) or
                    not isinstance(condition.get("agent_upload"), dict)):
                raise invalid("Original signed optimistic snapshot required")
            data_dir = os.environ.get("SEAFILE_DATA_DIR", "")
            if not os.path.isabs(data_dir):
                raise ContractError("EDIT_UNAVAILABLE", "Native file staging unavailable", 503)
            durable = self.runtime.optimistic_upload_receipt(grant, request_id)
            if (durable.get("intent_id") != intent or
                    durable.get("base_file_id") != condition["expected_file_id"] or
                    durable.get("content_digest") != grant["content_digest"] or
                    durable.get("snapshot_size") != size):
                raise ContractError("EDIT_CONFLICT", "Original signed snapshot intent is unavailable", 409)
            if durable["state"] == "prepared":
                with tempfile.NamedTemporaryFile(dir=Path(data_dir) / "httptemp",
                                                 prefix="cf-optimistic-edit-") as output:
                    stage(request, output, size=size, digest=grant["content_digest"])
                    from .native_publish import full_native_publish
                    try:
                        full_native_publish(call=_call, repo=grant["repo_id"],
                            staged=output.name, user=grant["native_user"],
                            condition=condition, mode="optimistic", timeout=180)
                    except NativeVersionConflict:
                        raise ContractError("RESOURCE_VERSION_CONFLICT",
                            "Cloud file changed since local edit began; local file retained", 409) from None
                    except Exception:
                        # Native may have published before reply loss; Query
                        # the atomic receipt instead of assuming failure.
                        pass
            durable = self.runtime.optimistic_upload_receipt(grant, request_id)
            if (durable.get("state") != "published" or
                    durable.get("intent_id") != intent or
                    durable.get("base_file_id") != condition["expected_file_id"] or
                    durable.get("content_digest") != grant["content_digest"] or
                    not _HEX40.fullmatch(durable.get("result_file_id") or "")):
                raise ContractError("PUBLICATION_UNCONFIRMED",
                    "Native optimistic file result unknown; recover original intent", 503)
            response = JsonResponse(dict(intent_id=intent, state="published",
                                         result_file_id=durable["result_file_id"],
                                         base_file_id=durable["base_file_id"]))
        except ContractError as exc:
            response = JsonResponse(exc.response(request_id), status=exc.status)
        except (ValueError, TypeError, UnicodeError):
            response = JsonResponse(invalid("Invalid optimistic local edit").response(request_id), status=400)
        except Exception:
            exc = ContractError("EDIT_UNAVAILABLE", "Optimistic upload unavailable", 503)
            response = JsonResponse(exc.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Request-ID"] = request_id
        return response
