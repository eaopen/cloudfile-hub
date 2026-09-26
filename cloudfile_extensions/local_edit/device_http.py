"""Browser own-device management only; never an Agent session/file endpoint."""
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.urls import path

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .device_runtime import DeviceManagementFactory
from .device_service import DeviceManagementService


class DeviceManagementView(DirectoryPolicyView):
    service_factory = None
    operation = "status"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Device management requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure device management required", 401)
            if request.GET or request.headers.get("Content-Encoding", "identity") != "identity":
                raise invalid("Device management takes uncompressed JSON without query")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            value = self._body(request)
            if self.operation not in {"pair-start", "pair-confirm", "status", "revoke"}:
                raise invalid("Device operation is unavailable")
            if not isinstance(self.service_factory, DeviceManagementFactory):
                raise ContractError("DEVICE_UNAVAILABLE", "Device runtime is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, DeviceManagementService):
                    raise RuntimeError("actual own-device management required")
                methods = {"pair-start": service.start_pairing, "pair-confirm": service.confirm_pairing,
                    "status": service.status, "revoke": service.revoke}
                response = JsonResponse(methods[self.operation](value))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            error = invalid("Invalid device request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("DEVICE_UNAVAILABLE", "Device runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


def device_routes(*, service_factory):
    if not isinstance(service_factory, DeviceManagementFactory):
        raise ValueError("actual native own-device management factory required")
    return [path("v1/devices/" + operation + "/", DeviceManagementView.as_view(
        service_factory=service_factory, operation=operation), name="local-device-" + operation)
        for operation in ("pair-start", "pair-confirm", "status", "revoke")]
