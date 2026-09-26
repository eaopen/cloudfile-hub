from unittest import TestCase

from cloudfile_extensions.events.outbox import projection_required


class SearchEventDispositionTest(TestCase):
    def test_managed_reads_and_new_unbound_definition_do_not_need_indexing(self):
        self.assertFalse(projection_required(dict(source="fileserver", action="file.download", resource_kind="file")))
        self.assertFalse(projection_required(dict(source="hub", action="tags.definition.created", result="succeeded", reason="tag_id:11111111-1111-4111-8111-111111111111")))

    def test_unknown_or_changed_definition_still_requires_projection(self):
        for action, reason in (("tags.definition.created", "tag_id:invalid"), ("tags.definition.updated", "tag_id:11111111-1111-4111-8111-111111111111")):
            self.assertTrue(projection_required(dict(source="hub", action=action, result="succeeded", reason=reason)))

    def test_known_identity_delegation_and_audit_delivery_facts_are_not_mutations(self):
        facts = [dict(source="hub", action="identity.bound", result="succeeded", target_user_id="employee"),
                 dict(source="hub", action="user.delegation.issue", result="succeeded", target_user_id="employee", subject_revision="epoch", repo_id="repo", path="/x", resource_kind="file"),
                 dict(source="hub", action="audit.export.download", result="attempted", repo_id="repo", job_id="job")]
        for fact in facts:
            self.assertFalse(projection_required(fact))
            self.assertTrue(projection_required({**fact, "resource_uid": "unexpected"}))
            self.assertTrue(projection_required({**fact, "source": "server"}))

    def test_unknown_identity_event_and_global_tag_update_are_not_ignored(self):
        self.assertTrue(projection_required(dict(source="hub", action="identity.unknown", result="succeeded")))
        self.assertTrue(projection_required(dict(source="hub", action="tags.definition.updated", result="succeeded", reason="tag_id:11111111-1111-4111-8111-111111111111")))
