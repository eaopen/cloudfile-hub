"""Public, read-only discovery; resource APIs retain native authentication."""
from django.http import JsonResponse
from django.urls import path
from django.views.decorators.http import require_GET

from .capabilities import capability_document


@require_GET
def capabilities(request):
    # Discovery contains no tenant/user/configuration data and needs no
    # administrator credential. Never turn a static schema into readiness.
    response = JsonResponse(capability_document())
    response['Cache-Control'] = 'no-store'
    return response


urlpatterns = [path('capabilities/', capabilities, name='cloudfile-v2-capabilities')]
