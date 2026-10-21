"""One explicit route assembly; no import-time registration or activation."""
from django.urls import path
from .http import EditingView
from .runtime import EditingFactory
from .upload import EditingUploadView, EditingCheckinView


def editing_routes(*, service_factory):
    from ..authorization.gunicorn import editing_service
    if not isinstance(service_factory, EditingFactory) and service_factory is not editing_service:
        raise ValueError('actual editing factory required')
    routes = [path('v1/' + operation + '/', EditingView.as_view(
        service_factory=service_factory, operation=operation), name='editing-' + operation)
        for operation in ('status', 'checkout', 'heartbeat', 'resume',
                          'abandon', 'cancel')]
    routes.append(path('v1/checkin/', EditingCheckinView.as_view(
        service_factory=service_factory), name='editing-checkin'))
    routes.append(path('v1/commit-file/', EditingUploadView.as_view(
        service_factory=service_factory), name='editing-commit-file'))
    return routes
