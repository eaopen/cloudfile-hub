"""UI capability derives from installed endpoint AND existing local app switch.

Actual signed upload authority always remains in Agent Runtime/Native Server.
"""
import unittest
from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY="isolated-app-capability",DEFAULT_CHARSET="utf-8")
from django.test import override_settings

from cloudfile_ext.features import enabled_features


class AgentFeatureGateTests(unittest.TestCase):
    def test_ordinary_agent_button_is_hidden_unless_both_release_gates_are_on(self):
        assert not enabled_features()["CF_AGENT_OPTIMISTIC_UPLOAD_READY"]
        with override_settings(CF_ENABLE_LOCAL_APP=True,
                               CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED=False):
            features=enabled_features()
            assert features["CF_ENABLE_LOCAL_APP"]
            assert features["CF_AGENT_OPTIMISTIC_UPLOAD_READY"] is False
        with override_settings(CF_ENABLE_LOCAL_APP=False,
                               CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED=True):
            assert not enabled_features()["CF_AGENT_OPTIMISTIC_UPLOAD_READY"]
        with override_settings(CF_ENABLE_LOCAL_APP=True,
                               CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED=True):
            assert enabled_features()["CF_AGENT_OPTIMISTIC_UPLOAD_READY"] is True
