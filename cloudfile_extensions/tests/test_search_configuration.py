from types import SimpleNamespace
from unittest import TestCase

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.configuration import require_configuration, validate_config


class SearchConfigurationTest(TestCase):
    def setUp(self):
        self.config = dict(endpoint="http://meilisearch:7700", index="resources_20260930",
            generation="20260930", read_key="private-read", write_key="private-write", cursor_secret=b"s" * 32)
        self.settings = SimpleNamespace(CLOUDFILE_RESOURCE_SEARCH_ENABLED=True,
            CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_AUTHORIZATION_ENABLED=True,
            CLOUDFILE_RESOURCE_SECRET=b"r" * 32, CLOUDFILE_RESOURCE_LIFECYCLE_READER=lambda *_: None,
            CLOUDFILE_RESOURCE_SEARCH_CONFIG=self.config)

    def test_default_off_requires_no_search_resources(self):
        self.assertIsNone(require_configuration(SimpleNamespace()))
        self.assertEqual(require_configuration(self.settings), self.config)

    def test_dependencies_and_fixed_private_configuration_are_required(self):
        for name, value in [("CLOUDFILE_OIDC_ENABLED", False), ("CLOUDFILE_AUTHORIZATION_ENABLED", False),
                ("CLOUDFILE_RESOURCE_LIFECYCLE_READER", None), ("CLOUDFILE_RESOURCE_SECRET", b"short"),
                ("CLOUDFILE_RESOURCE_SEARCH_ENABLED", "true")]:
            previous = getattr(self.settings, name)
            setattr(self.settings, name, value)
            with self.assertRaises(ValueError):
                require_configuration(self.settings)
            setattr(self.settings, name, previous)
        for changes in [dict(cursor_secret=b"short"), dict(index="arbitrary/route"),
                dict(endpoint="http://meilisearch:7700/indexes/other"), dict(extra="unknown")]:
            with self.assertRaises((ValueError, ContractError)):
                validate_config({**self.config, **changes})
