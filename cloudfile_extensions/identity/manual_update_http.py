"""Explicit Web replacement through existing native conditional publication."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile
import time
from uuid import uuid4

from django.http import JsonResponse
from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware
from django.views import View

from ..common.errors import ContractError, invalid
from ..authorization.core import PolicyCore
from ..authorization.read import ContentMetadataWriteAuthority
from ..resources.paths import resource_ref
from .native_session import SESSION_REFERENCE_KEY
from .read_ticket_http import native_download_actor
from .resources import LoginResources
from .session_authority import OIDCSessionAuthority
from .ticket_transport import _call


class OIDCManualUpdateView(View):
    resources = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Manual update requires POST", 405)
            if (request.GET or request.headers.get("Authorization")
                    or request.headers.get("Content-Encoding")):
                raise invalid("Manual update requires a native session and multipart form")
            actor = native_download_actor(request)
            if not isinstance(self.resources, LoginResources):
                raise ContractError("POLICY_UNAVAILABLE", "Manual update runtime is unavailable", 503)
            authority = OIDCSessionAuthority(self.resources)
            authority.check(request)
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            if request.content_type != "multipart/form-data":
                raise ContractError("UNSUPPORTED_MEDIA_TYPE", "Multipart form is required", 415)
            if (set(request.POST) != {"repo_id", "path", "head_id"}
                    or any(len(request.POST.getlist(key)) != 1 for key in request.POST)
                    or set(request.FILES) != {"file"} or len(request.FILES.getlist("file")) != 1):
                raise invalid("One explicit file and expected head are required")
            reference = resource_ref(dict(repo_id=request.POST["repo_id"],
                path=request.POST["path"], kind="file"))
            head = request.POST["head_id"]
            if not re.fullmatch(r"[0-9a-f]{40}", head):
                raise invalid("Explicit expected head is required")
            uploaded = request.FILES["file"]
            if uploaded.size > 512 * 1024 * 1024:
                raise ContractError("REQUEST_TOO_LARGE", "Manual update exceeds 512 MiB", 413)
            with self.resources.resources.preparation(actor.user_id, request_id) as preparation:
                preparation.prepare(actor.user_id)
                if preparation.state.username(actor.user_id) != actor.native_username:
                    raise ContractError("ACCESS_DENIED", "Native identity changed", 403)
                policy = settings.CLOUDFILE_POLICY_CONFIG
                preflight = ContentMetadataWriteAuthority(preparation,
                    PolicyCore(policy["core_library"]), request_id=request_id,
                    cloud_mode=policy["cloud_mode"])
                preflight.consume(reference, lambda cursor, target: None)
                from seaserv import seafile_api
                if seafile_api.check_quota(reference["repo_id"], uploaded.size) != 0:
                    raise ContractError("QUOTA_EXCEEDED", "Library quota is unavailable", 403)
                with authority.guard(request):
                    proof = dict(deepcopy(request.session[SESSION_REFERENCE_KEY]),
                                 session_key=request.session.session_key)
                current = preparation.contexts.current(actor.user_id)
                if current is None:
                    raise ContractError("SUBJECT_UNAVAILABLE", "Current subject is unavailable", 503)
                provider = preparation.state.provider
                oidc = "cf_oidc_" + proof["scope_hash"][:24]
                condition = dict(head_id=head,
                    context=dict(provider=provider, userId=actor.user_id, epoch=current["context_epoch"]),
                    scopes=[dict(type="provider", provider=provider, external_id=provider),
                        dict(type="provider", provider=oidc, external_id=oidc),
                        dict(type="user", provider=provider, external_id=actor.user_id),
                        dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])],
                    oidc_session=proof)
                # Trusted shared data directory; the submitted filename never
                # selects the staging path. Cleanup also runs on RPC failure.
                data_dir = os.environ.get("SEAFILE_DATA_DIR", "")
                if not os.path.isabs(data_dir):
                    raise ContractError("POLICY_UNAVAILABLE", "Upload staging is unavailable", 503)
                temporary = Path(data_dir) / "httptemp"
                with tempfile.NamedTemporaryFile(dir=temporary, prefix="cf-web-update-") as staged:
                    for chunk in uploaded.chunks():
                        staged.write(chunk)
                    staged.flush()
                    parent, _, filename = reference["path"].rpartition("/")
                    try:
                        object_id = _call("seafile_cloudfile_put_file_with_barriers",
                            (reference["repo_id"], staged.name, parent or "/", filename,
                             actor.native_username, json.dumps(condition, separators=(",", ":"))),
                            time.monotonic() + 30)
                    except Exception:
                        raise ContractError("PUBLICATION_UNCONFIRMED",
                            "Native update was refused or completion is unconfirmed", 503) from None
            if not isinstance(object_id, str) or not re.fullmatch(r"[0-9a-f]{40}", object_id):
                raise ContractError("PUBLICATION_UNCONFIRMED", "Native completion is unconfirmed", 503)
            response = JsonResponse(dict(object_id=object_id, request_id=request_id))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("POLICY_UNAVAILABLE", "Manual update runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response
