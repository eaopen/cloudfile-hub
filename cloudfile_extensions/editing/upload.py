"""One-file OIDC upload; native Branch transaction owns publication and receipt."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views import View

from ..authorization.http import DirectoryPolicyView
from ..authorization.gunicorn import login_resources_scope
from ..common.errors import ContractError, invalid
from ..resources.paths import resource_ref
from .service import EditingService
from .store import uuid

EMPTY_CONTENT_DIGEST = hashlib.sha256(b"").hexdigest()


def _native_condition(service, authority, request, actor, ref, head, proof, intent_id, resource_uid):
    from ..identity.native_session import SESSION_REFERENCE_KEY
    preparation = service.resources.write_authority.preparation
    current = preparation.contexts.current(actor.user_id)
    if current is None:
        raise ContractError("SUBJECT_UNAVAILABLE", "Current subject is unavailable", 503)
    provider = preparation.state.provider
    with authority.guard(request):
        oidc_proof = deepcopy(request.session[SESSION_REFERENCE_KEY])
        oidc_proof["session_key"] = request.session.session_key
    oidc = "cf_oidc_" + oidc_proof["scope_hash"][:24]
    return dict(head_id=head, path=ref["path"],
        context=dict(provider=provider, userId=actor.user_id,
                     epoch=current["context_epoch"]),
        scopes=[dict(type="provider", provider=provider, external_id=provider),
            dict(type="provider", provider=oidc, external_id=oidc),
            dict(type="user", provider=provider, external_id=actor.user_id),
            dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])],
        oidc_session=oidc_proof,
        editing=dict(repo_id=ref["repo_id"], resource_uid=resource_uid,
            guard_id=proof["guard_id"], generation=str(proof["generation"]),
            credential_epoch=str(proof["credential_epoch"]), holder=service.holder,
            token=proof["token"], intent_id=intent_id,
            base_file_id=proof["base_file_id"]))


def _native_version_conflict(ref, expected_head, expected_file_id):
    """Only classify a refused native call; never authorize publication."""
    from ..identity.ticket_transport import _call
    deadline = time.monotonic() + 5
    repo = _call("seafile_get_repo", (ref["repo_id"],), deadline)
    heads = [name for name in ("head_cmmt_id", "head-cmmt-id") if name in repo]
    if len(heads) != 1 or not isinstance(repo[heads[0]], str):
        return False
    current_head = repo[heads[0]]
    if current_head != expected_head:
        return True
    current_file = _call("seafile_get_file_id_by_commit_and_path",
        (ref["repo_id"], current_head, ref["path"]), deadline)
    return current_file != expected_file_id


class EditingUploadView(View):
    service_factory = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            from ..identity.native_session import SESSION_REFERENCE_KEY
            from ..identity.read_ticket_http import native_download_actor
            from ..identity.session_authority import OIDCSessionAuthority
            from ..identity.ticket_transport import _call
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "File commit requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure session is required", 401)
            if request.GET or request.headers.get("Authorization") or request.headers.get("Content-Encoding"):
                raise invalid("File commit requires a native session multipart form")
            actor = native_download_actor(request)
            with login_resources_scope() as resources:
                authority = OIDCSessionAuthority(resources)
                authority.check(request)
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                if request.content_type != "multipart/form-data":
                    raise ContractError("UNSUPPORTED_MEDIA_TYPE", "Multipart form is required", 415)
                fields = {"repo_id", "path", "guard_id", "generation", "credential_epoch",
                          "token", "intent_id", "base_file_id", "head_id", "action"}
                if (set(request.POST) not in (fields, fields | {"source_identity"}) or
                        any(len(request.POST.getlist(key)) != 1 for key in request.POST) or
                        set(request.FILES) != {"file"} or len(request.FILES.getlist("file")) != 1):
                    raise invalid("One file and exact Checkout fields are required")
                key = request.headers.get("Idempotency-Key")
                if not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                ref = resource_ref(dict(repo_id=request.POST["repo_id"],
                    path=request.POST["path"], kind="file"))
                head = request.POST["head_id"]
                if not re.fullmatch(r"[0-9a-f]{40}", head):
                    raise invalid("Explicit native head is required")
                if not re.fullmatch(r"[1-9][0-9]{0,19}", request.POST["generation"]) or not re.fullmatch(
                        r"[1-9][0-9]{0,19}", request.POST["credential_epoch"]):
                    raise invalid("Canonical editing generation is required")
                if request.POST["action"] not in ("commit", "checkin"):
                    raise invalid("Commit or checkin action is required")
                intent_id = uuid(request.POST["intent_id"])
                uploaded = request.FILES["file"]
                if uploaded.size > 128 * 1024 * 1024:
                    raise ContractError("REQUEST_TOO_LARGE", "Single-file commit exceeds 128 MiB", 413)
                data_dir = os.environ.get("SEAFILE_DATA_DIR", "")
                if not os.path.isabs(data_dir):
                    raise ContractError("EDIT_UNAVAILABLE", "Native staging is unavailable", 503)
                digest = hashlib.sha256()
                with tempfile.NamedTemporaryFile(dir=Path(data_dir) / "httptemp",
                                                 prefix="cf-edit-") as staged:
                    for chunk in uploaded.chunks():
                        digest.update(chunk)
                        staged.write(chunk)
                    staged.flush()
                    os.fsync(staged.fileno())
                    os.fchmod(staged.fileno(), 0o400)
                    snapshot_size = staged.tell()
                    if snapshot_size > 128 * 1024 * 1024:
                        raise ContractError("REQUEST_TOO_LARGE", "Snapshot exceeds 128 MiB", 413)
                    content_digest = digest.hexdigest()
                    proof = {name: request.POST[name] for name in
                        ("guard_id", "token", "base_file_id", "action")}
                    proof.update(generation=int(request.POST["generation"]),
                        credential_epoch=int(request.POST["credential_epoch"]),
                        reference=ref, intent_id=intent_id, content_digest=content_digest,
                        snapshot=dict(id=intent_id, size=snapshot_size,
                            source=request.POST.get("source_identity", uploaded.name)))
                    with self.service_factory(request, request_id) as service:
                        if not isinstance(service, EditingService):
                            raise ContractError("EDIT_UNAVAILABLE", "Editing runtime is unavailable", 503)
                        if actor.user_id != service.resources.write_authority.actor:
                            raise ContractError("ACCESS_DENIED", "Editing identity changed", 403)
                        try:
                            previous = service.query(dict(reference=ref, intent_id=intent_id))
                        except ContractError as error:
                            if error.code != "NOT_FOUND":
                                raise
                            previous = None
                        if previous is not None:
                            expected = dict(guard_id=proof["guard_id"],
                                generation=proof["generation"], credential_epoch=proof["credential_epoch"],
                                expected_file_id=proof["base_file_id"],
                                content_digest=content_digest, action=proof["action"])
                            if any(previous.get(name) != (str(value) if name in
                                    ("generation", "credential_epoch") else value)
                                    for name, value in expected.items()):
                                raise ContractError("IDEMPOTENCY_CONFLICT", "Intent content changed", 409)
                            if previous["state"] == "published":
                                replay = service.command("prepare", proof, idempotency_key=key)["receipt"]
                                if replay.get("intent_id") != intent_id:
                                    raise ContractError("IDEMPOTENCY_CONFLICT", "Intent retry changed", 409)
                                result = previous
                            elif previous["state"] != "prepared":
                                raise ContractError("EDIT_CONFLICT", "Intent is no longer prepared", 409)
                            else:
                                result = None
                        else:
                            result = None
                        if result is None:
                            prepared = service.command("prepare", proof, idempotency_key=key)
                            prepared_intent = prepared["receipt"]
                            if (prepared_intent["intent_id"] != intent_id or
                                    prepared_intent["state"] not in ("prepared", "published")):
                                raise ContractError("EDIT_UNAVAILABLE", "Prepared intent is unavailable", 503)
                            condition = _native_condition(service, authority, request, actor,
                                ref, head, proof, intent_id,
                                (previous or prepared_intent)["resource_uid"])
                            parent, _, filename = ref["path"].rpartition("/")
                            try:
                                object_id = _call("seafile_cloudfile_publish_edit",
                                    (ref["repo_id"], staged.name, parent or "/", filename,
                                     actor.native_username, json.dumps(condition, separators=(",", ":"))),
                                    time.monotonic() + 180)
                            except Exception:
                                object_id = None
                            result = service.query(dict(reference=ref, intent_id=intent_id))
                            if (result["state"] != "published" or
                                    (object_id is not None and object_id != result["result_file_id"])):
                                if result["state"] == "prepared":
                                    try:
                                        if _native_version_conflict(ref, head, proof["base_file_id"]):
                                            raise ContractError("RESOURCE_VERSION_CONFLICT",
                                                "Native file version changed; Checkout remains held", 409)
                                    except ContractError:
                                        raise
                                    except Exception:
                                        pass
                                raise ContractError("PUBLICATION_UNCONFIRMED",
                                    "Native publication is incomplete or unconfirmed", 503)
            response = JsonResponse(dict(intent=result, request_id=request_id))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, OverflowError):
            error = invalid("Invalid editing request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("EDIT_UNAVAILABLE", "Editing service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response


class EditingCheckinView(DirectoryPolicyView):
    """No-content Checkin; the native Branch transaction owns the release."""
    service_factory = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            from ..identity.read_ticket_http import native_download_actor
            from ..identity.session_authority import OIDCSessionAuthority
            from ..identity.ticket_transport import _call
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Checkin requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure session is required", 401)
            if request.GET or request.headers.get("Authorization") or request.headers.get("Content-Encoding"):
                raise invalid("Checkin requires a native session JSON request")
            actor = native_download_actor(request)
            with login_resources_scope() as resources:
                authority = OIDCSessionAuthority(resources)
                authority.check(request)
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                body = self._body(request)
                fields = {"repo_id", "path", "guard_id", "generation", "credential_epoch",
                          "token", "intent_id", "base_file_id", "head_id"}
                if set(body) != fields:
                    raise invalid("Exact unchanged Checkin fields are required")
                ref = resource_ref(dict(repo_id=body["repo_id"], path=body["path"], kind="file"))
                if not re.fullmatch(r"[0-9a-f]{40}", body["head_id"]):
                    raise invalid("Explicit native head is required")
                for name in ("generation", "credential_epoch"):
                    if not isinstance(body[name], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", body[name]):
                        raise invalid("Canonical editing generation is required")
                intent_id = uuid(body["intent_id"])
                key = request.headers.get("Idempotency-Key")
                if not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                proof = {name: body[name] for name in ("guard_id", "token", "base_file_id")}
                proof.update(generation=int(body["generation"]),
                    credential_epoch=int(body["credential_epoch"]), reference=ref,
                    intent_id=intent_id, content_digest=EMPTY_CONTENT_DIGEST,
                    staged_file_id=body["base_file_id"], action="checkin-unchanged")
                with self.service_factory(request, request_id) as service:
                    if not isinstance(service, EditingService):
                        raise ContractError("EDIT_UNAVAILABLE", "Editing runtime is unavailable", 503)
                    if actor.user_id != service.resources.write_authority.actor:
                        raise ContractError("ACCESS_DENIED", "Editing identity changed", 403)
                    try:
                        previous = service.query(dict(reference=ref, intent_id=intent_id))
                    except ContractError as error:
                        if error.code != "NOT_FOUND":
                            raise
                        previous = None
                    if previous is not None:
                        expected = dict(guard_id=proof["guard_id"],
                            generation=body["generation"], credential_epoch=body["credential_epoch"],
                            expected_file_id=proof["base_file_id"],
                            staged_file_id=proof["base_file_id"],
                            content_digest=EMPTY_CONTENT_DIGEST, action="checkin-unchanged")
                        if any(previous.get(name) != value for name, value in expected.items()):
                            raise ContractError("IDEMPOTENCY_CONFLICT", "Intent content changed", 409)
                        if previous["state"] == "published":
                            replay = service.command("prepare", proof, idempotency_key=key)["receipt"]
                            if replay.get("intent_id") != intent_id:
                                raise ContractError("IDEMPOTENCY_CONFLICT", "Intent retry changed", 409)
                            result = previous
                        elif previous["state"] != "prepared":
                            raise ContractError("EDIT_CONFLICT", "Intent is no longer prepared", 409)
                        else:
                            result = None
                    else:
                        result = None
                    if result is None:
                        prepared = service.command("prepare", proof, idempotency_key=key)["receipt"]
                        if prepared["intent_id"] != intent_id or prepared["state"] not in ("prepared", "published"):
                            raise ContractError("EDIT_UNAVAILABLE", "Prepared Checkin is unavailable", 503)
                        condition = _native_condition(service, authority, request, actor,
                            ref, body["head_id"], proof, intent_id,
                            (previous or prepared)["resource_uid"])
                        try:
                            object_id = _call("seafile_cloudfile_checkin_edit",
                                (ref["repo_id"], ref["path"], actor.native_username,
                                 json.dumps(condition, separators=(",", ":"))),
                                time.monotonic() + 30)
                        except Exception:
                            object_id = None
                        result = service.query(dict(reference=ref, intent_id=intent_id))
                        if (result["state"] != "published" or
                                (object_id is not None and object_id != result["result_file_id"])):
                            if result["state"] == "prepared":
                                try:
                                    if _native_version_conflict(ref, body["head_id"], proof["base_file_id"]):
                                        raise ContractError("RESOURCE_VERSION_CONFLICT",
                                            "Native file version changed; Checkout remains held", 409)
                                except ContractError:
                                    raise
                                except Exception:
                                    pass
                            raise ContractError("PUBLICATION_UNCONFIRMED",
                                "Native Checkin is incomplete or unconfirmed", 503)
            response = JsonResponse(dict(intent=result, request_id=request_id))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, OverflowError, TypeError):
            error = invalid("Invalid editing request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("EDIT_UNAVAILABLE", "Editing service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response
