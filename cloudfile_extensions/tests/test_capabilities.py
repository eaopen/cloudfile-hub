import unittest

from cloudfile_extensions.capabilities import build_capability_document


class CapabilityDocumentTest(unittest.TestCase):
    def test_base_contract_is_enabled(self):
        document = build_capability_document()

        self.assertEqual(document["version"], "v0.2")
        self.assertEqual(document["contract_version"], "1.0")
        self.assertEqual(
            document["capabilities"]["extension.contract"],
            {"enabled": True, "version": "1.0"},
        )

    def test_configured_capabilities_are_normalized(self):
        document = build_capability_document({
            "search.fulltext": {
                "enabled": True,
                "version": "1",
                "provider": "meilisearch",
            },
            "file.lock": False,
        })

        self.assertEqual(
            document["capabilities"]["search.fulltext"]["provider"],
            "meilisearch",
        )
        self.assertEqual(document["capabilities"]["file.lock"], {"enabled": False})

    def test_invalid_capability_is_rejected(self):
        with self.assertRaises(ValueError):
            build_capability_document({"Project Feature": True})

        with self.assertRaises(ValueError):
            build_capability_document({"search.fulltext": {"enabled": "yes"}})

        with self.assertRaises(ValueError):
            build_capability_document({
                "auth.oidc": {
                    "enabled": True,
                    "client_secret": "must-not-be-public",
                },
            })


if __name__ == "__main__":
    unittest.main()
