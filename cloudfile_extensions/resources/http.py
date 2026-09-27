"""Controlled resource HTTP adapters; no registration or readiness assertion.

Deployment supplies resource_service as the authenticated owned factory. These
Write adapters require durable idempotency. Native lifecycle and release gates
must be completed before deployment registers any of these views.
"""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from .service import ResourceService


class ResourceResolveView(DirectoryPolicyView):
    service_factory = None
    operation = "resolve"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            methods = {"resolve": "POST", "batch": "POST", "user_catalog": "GET", "attributes": "POST",
                "tag_ids": "POST", "tag_values": "POST", "tag_definition": "PATCH"}
            if self.operation not in methods:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource operation is unavailable", 503)
            expected = methods[self.operation]
            if request.method != expected or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this resource target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.headers.get("Authorization") or request.headers.get("Content-Encoding"):
                raise invalid("Resource Web requests do not accept machine credentials or encoded bodies")
            if self.operation == "user_catalog":
                allowed = {"repo_id", "limit", "after"}
                if (set(request.GET) - allowed or "repo_id" not in request.GET
                        or any(len(request.GET.getlist(key)) != 1 for key in request.GET)
                        or request.read(1)):
                    raise invalid("Invalid tag dictionary query")
                limit = request.GET.get("limit", "50")
                if not re.fullmatch(r"[1-9][0-9]{0,2}", limit) or int(limit) > 100:
                    raise invalid("Invalid tag page size")
                body = dict(repo_id=request.GET["repo_id"], limit=int(limit))
                if "after" in request.GET:
                    body["after"] = request.GET["after"]
            else:
                if request.GET:
                    raise invalid("Resource resolution takes no query parameters")
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                body = self._body(request)
                if self.operation == "attributes":
                    object_fields(body, ("resource", "expected_revision", "changes"))
                    object_fields(body["changes"], ("description",))
            writes = {"attributes", "tag_ids", "tag_values", "tag_definition"}
            key = None
            if self.operation in writes:
                key = request.headers.get("Idempotency-Key")
                if key is None:
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                if not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
                    raise invalid("Invalid resource idempotency key")
                if self.operation == "tag_definition" and request.headers.get("If-Match") is None:
                    raise ContractError("PRECONDITION_REQUIRED", "If-Match is required", 428)
            if not callable(self.service_factory):
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, ResourceService):
                    raise RuntimeError("invalid resource service assembly")
                if self.operation == "user_catalog":
                    result = service.list_user_tag_definitions(body)
                elif self.operation == "resolve":
                    result = service.resolve({"reference": body})
                elif self.operation == "batch":
                    result = service.batch_resolve(body)
                else:
                    if self.operation == "tag_definition":
                        value, changed = service.update_user_tag_definition(body,
                            if_match=request.headers.get("If-Match"), idempotency_key=key)
                    else:
                        if self.operation == "attributes":
                            object_fields(body, ("resource", "expected_revision", "changes"))
                            body = dict(reference=body["resource"], revision=body["expected_revision"], changes=body["changes"])
                        method = {"attributes": service.update_attributes,
                            "tag_ids": service.replace_user_tags,
                            "tag_values": service.replace_user_tag_values}[self.operation]
                        value, changed = method(body, idempotency_key=key)
                    result = value
                status = 201 if self.operation == "attributes" and changed else 200
                # Local application mappings belong to v0.4, not this Web API.
                if isinstance(result, dict):
                    result = dict(result)
                    result.pop("local_open_type", None)
                    if self.operation == "batch":
                        result["items"] = [dict(item, snapshot={key: value for key, value in item["snapshot"].items()
                            if key != "local_open_type"}) if "snapshot" in item else item
                            for item in result["items"]]
                response = JsonResponse(result, status=status)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("RESOURCE_UNAVAILABLE", "Resource service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


class UserTagCatalogView(ResourceResolveView):
    operation = "user_catalog"
    http_method_names = ["get"]


class ResourceAttributesView(ResourceResolveView):
    operation = "attributes"


class ResourceBatchView(ResourceResolveView):
    operation = "batch"


class ResourceUserTagsView(ResourceResolveView):
    operation = "tag_ids"


class ResourceUserTagValuesView(ResourceResolveView):
    operation = "tag_values"


class UserTagDefinitionView(ResourceResolveView):
    operation = "tag_definition"
    http_method_names = ["patch"]
