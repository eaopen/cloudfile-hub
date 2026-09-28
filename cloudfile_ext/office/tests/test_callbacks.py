# -*- coding: utf-8 -*-

from cloudfile_ext.office.idempotency import dedupe_key


def test_dedupe_key_changes_with_each_save_identity():
    first = dedupe_key({'key': 'document', 'status': 2, 'url': 'https://doc/1'})
    assert first == dedupe_key({'key': 'document', 'status': 2, 'url': 'https://doc/1'})
    assert first != dedupe_key({'key': 'document', 'status': 6, 'url': 'https://doc/1'})
    assert first != dedupe_key({'key': 'document', 'status': 2, 'url': 'https://doc/2'})
