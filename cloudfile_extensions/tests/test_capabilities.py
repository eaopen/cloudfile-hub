import unittest

from cloudfile_extensions.capabilities import build_capability_document
from cloudfile_extensions.registry import CapabilityImplementation, ImplementationRegistry


class CapabilityDocumentTest(unittest.TestCase):
    def test_base_contract_is_enabled(self):
        document = build_capability_document()

        self.assertEqual(document["version"], "v0.2")
        self.assertEqual(document["contract_version"], "1.0")
        self.assertEqual(
            document["capabilities"]["extension.contract"],
            {"enabled": True, "version": "1.0"},
        )
        self.assertEqual(document["capabilities"]["library.admin.manage"],
                         {"enabled": True, "version": "1"})
        self.assertEqual(document["capabilities"]["library.config.manage"],
                         {"enabled": True, "version": "1"})

    def test_configured_capabilities_are_normalized(self):
        document = build_capability_document({
            "search.resources": {
                "enabled": True,
                "version": "1",
                "provider": "meilisearch",
            },
            "file.lock": False,
        })

        self.assertEqual(
            document["capabilities"]["search.resources"]["provider"],
            "meilisearch",
        )
        self.assertEqual(document["capabilities"]["file.lock"], {"enabled": False, "version": "1"})
        self.assertFalse(document["capabilities"]["search.resources"]["enabled"])

    def test_configuration_cannot_enable_unimplemented_or_unknown_capabilities(self):
        document = build_capability_document({
            "auth.oidc": True, "directory.acl": True, "unknown.feature": True,
        })
        for name in ("auth.oidc", "directory.acl", "unknown.feature"):
            self.assertFalse(document["capabilities"][name]["enabled"])

    def test_native_webdav_requires_explicit_integration_flag(self):
        requested = {"protocol.webdav": True}
        self.assertFalse(build_capability_document(requested)["capabilities"]["protocol.webdav"]["enabled"])
        self.assertTrue(build_capability_document(requested, webdav_enabled=True)["capabilities"]["protocol.webdav"]["enabled"])
        self.assertFalse(build_capability_document({"protocol.webdav": False}, webdav_enabled=True)["capabilities"]["protocol.webdav"]["enabled"])

    def test_registered_extension_requires_request_and_dependencies(self):
        implementations = ImplementationRegistry()
        implementations.register_extension("adapter", "adapter.audit", CapabilityImplementation("1", True))
        implementations.register_extension("adapter", "adapter.export", CapabilityImplementation("1", True, dependencies=("adapter.audit",)))
        document = build_capability_document({"adapter.export": True}, implementation_registry=implementations)
        self.assertFalse(document["capabilities"]["adapter.export"]["enabled"])
        document = build_capability_document({"adapter.export": True, "adapter.audit": True}, implementation_registry=implementations)
        self.assertTrue(document["capabilities"]["adapter.export"]["enabled"])

    def test_extension_cannot_replace_core_or_another_namespace(self):
        implementations = ImplementationRegistry()
        for namespace, name in (("search", "search.resources"), ("adapter", "auth.oidc")):
            with self.assertRaises(ValueError):
                implementations.register_extension(namespace, name, CapabilityImplementation("1", True))
        implementations.register_extension("adapter", "adapter.audit", CapabilityImplementation("1", True))
        with self.assertRaises(ValueError):
            implementations.register_extension("adapter", "adapter.audit", CapabilityImplementation("1", True))

    def test_configured_version_does_not_forge_implementation_version(self):
        document = build_capability_document({"auth.basic": {"enabled": True, "version": "999"}})
        self.assertEqual(document["capabilities"]["auth.basic"], {"enabled": False, "version": "14"})

    def test_dependency_cycles_are_rejected(self):
        implementations = ImplementationRegistry()
        implementations.register_extension("adapter", "adapter.a", CapabilityImplementation("1", True, dependencies=("adapter.b",)))
        implementations.register_extension("adapter", "adapter.b", CapabilityImplementation("1", True, dependencies=("adapter.a",)))
        with self.assertRaises(ValueError):
            build_capability_document(implementation_registry=implementations)

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
        with self.assertRaises(ValueError):
            build_capability_document({"auth.basic": {"version": None}})


if __name__ == "__main__":
    unittest.main()


class AnnotationRuntimeCapabilityTest(unittest.TestCase):
    def host(self):
        import os
        from unittest.mock import Mock
        from cloudfile_extensions.authorization.host import PolicyHost
        from cloudfile_extensions.resources.runtime import ResourceServiceFactory
        from cloudfile_extensions.identity.resources import LoginResources
        host = Mock(spec=PolicyHost)
        host.pid = os.getpid(); host.closed = False; host.draining = False
        host.deployment = Mock(resource_factory=Mock(spec=ResourceServiceFactory),
            login_resources=Mock(spec=LoginResources))
        return host

    def document(self, host, **options):
        from cloudfile_extensions.capabilities import annotation_implementation_registry
        registry = annotation_implementation_registry(host, annotations_enabled=options.get('enabled', True), oidc_enabled=True)
        return build_capability_document(options.get('configured'), implementation_registry=registry)['capabilities']

    def test_live_worker_exposes_only_basic_annotation_capabilities(self):
        capabilities = self.document(self.host())
        for name in ('resource.description', 'resource.local-open-type', 'tag.extended'):
            self.assertTrue(capabilities[name]['enabled'])
        for name in ('search.resources', 'local.open-edit', 'file.lock'):
            self.assertFalse(capabilities[name]['enabled'])

    def test_missing_closed_inherited_worker_or_disabled_flag_cannot_publish(self):
        self.assertFalse(self.document(None)['resource.description']['enabled'])
        host = self.host()
        self.assertFalse(self.document(host, enabled=False)['resource.description']['enabled'])
        host.closed = True
        self.assertFalse(self.document(host)['resource.description']['enabled'])
        host.closed = False; host.pid = -1
        self.assertFalse(self.document(host)['resource.description']['enabled'])
        host = self.host(); host.deployment.resource_factory = None
        self.assertFalse(self.document(host)['resource.description']['enabled'])

    def test_explicit_disable_and_dependency_disable_are_preserved(self):
        for configured in ({'tag.extended': False}, {'directory.acl': False}):
            self.assertFalse(self.document(self.host(), configured=configured)['tag.extended']['enabled'])


class ManagementCapabilityTest(unittest.TestCase):
    def test_directory_crud_does_not_manufacture_library_publish_readiness(self):
        import os
        from unittest.mock import Mock
        from cloudfile_extensions.authorization.host import PolicyHost
        from cloudfile_extensions.authorization.runtime import PolicyServiceFactory
        from cloudfile_extensions.identity.resources import LoginResources
        from cloudfile_extensions.capabilities import management_implementation_registry
        from cloudfile_extensions.registry import registry
        host = Mock(spec=PolicyHost)
        host.pid = os.getpid(); host.closed = False; host.draining = False
        host.deployment = Mock(factory=Mock(spec=PolicyServiceFactory),
            login_resources=Mock(spec=LoginResources))
        ready = management_implementation_registry(registry, host, authorization_enabled=True,
            oidc_enabled=True)
        self.assertTrue(ready.implementations['directory.acl.manage'].implemented)
        self.assertTrue(build_capability_document(implementation_registry=ready)['capabilities']['directory.acl.manage']['enabled'])
        self.assertTrue(ready.implementations['library.shares.manage'].implemented)
        self.assertTrue(build_capability_document(implementation_registry=ready)['capabilities']['library.shares.manage']['enabled'])
        self.assertTrue(ready.implementations['library.admin.manage'].implemented)
        host.closed = True
        closed = management_implementation_registry(registry, host, authorization_enabled=True)
        self.assertFalse(closed.implementations['directory.acl.manage'].implemented)


class AuditQueryCapabilityTest(unittest.TestCase):
    def test_query_transport_is_distinct_from_complete_audit(self):
        import os
        from unittest.mock import Mock
        from cloudfile_extensions.authorization.host import PolicyHost
        from cloudfile_extensions.events.runtime import AuditQueryFactory
        from cloudfile_extensions.capabilities import audit_query_implementation_registry
        from cloudfile_extensions.registry import registry
        host = Mock(spec=PolicyHost)
        host.pid = os.getpid(); host.closed = False; host.draining = False
        host.deployment = Mock(audit_factory=Mock(spec=AuditQueryFactory))
        ready = audit_query_implementation_registry(registry, host, audit_query_enabled=True)
        capabilities = build_capability_document(implementation_registry=ready)['capabilities']
        self.assertTrue(capabilities['audit.query']['enabled'])
        self.assertFalse(capabilities['audit.log']['enabled'])
        for closed in (audit_query_implementation_registry(registry, host, audit_query_enabled=False),
                       audit_query_implementation_registry(registry, None, audit_query_enabled=True)):
            self.assertFalse(build_capability_document(implementation_registry=closed)['capabilities']['audit.query']['enabled'])
