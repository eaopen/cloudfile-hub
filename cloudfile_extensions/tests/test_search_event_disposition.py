from unittest import TestCase

from cloudfile_extensions.events.outbox import projection_required


class SearchEventDispositionTest(TestCase):
    def test_managed_reads_and_new_unbound_definition_do_not_need_indexing(self):
        self.assertFalse(projection_required(dict(source="fileserver", action="file.download", resource_kind="file")))
        self.assertFalse(projection_required(dict(source="hub", action="tags.definition.created", result="succeeded", reason="tag_id:11111111-1111-4111-8111-111111111111")))

    def test_unknown_or_changed_definition_still_requires_projection(self):
        for action, reason in (("tags.definition.created", "tag_id:invalid"), ("tags.definition.updated", "tag_id:11111111-1111-4111-8111-111111111111")):
            self.assertTrue(projection_required(dict(source="hub", action=action, result="succeeded", reason=reason)))
