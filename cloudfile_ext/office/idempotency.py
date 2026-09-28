# -*- coding: utf-8 -*-
"""Django-free callback identity helpers."""

import hashlib


def dedupe_key(payload):
    """Key one completed OnlyOffice save by its immutable callback identity."""
    value = '\x1f'.join((
        str(payload.get('key', '')),
        str(payload.get('status', '')),
        str(payload.get('url', '')),
    ))
    return 'cloudfile_onlyoffice_completed_' + hashlib.sha256(
        value.encode('utf-8')).hexdigest()
