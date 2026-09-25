from django.urls import path

from .api import CapabilitiesView


app_name = "cloudfile_extensions"

urlpatterns = [
    path("capabilities/", CapabilitiesView.as_view(), name="capabilities"),
]
