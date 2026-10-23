"""Deterministic library ACL snapshots shared by batch GET and atomic PUT.

No new ACL tables or policy evaluator: read/write decisions remain in Authority.
"""
from dataclasses import asdict
from hashlib import sha256
import json

from .acl_policy import Rule


CONTRACT = 'cf-acl-library-batch-v1'


def key_of(rule):
    return (rule.path, rule.subject_type, rule.namespace, rule.external_id)


def fingerprint(rows):
    """Hash all of this provider's rules, including CAS revisions.

    Sorting in application code avoids reliance on a database collation or
    secondary-index ordering. Both management GET and locked PUT use this.
    """
    entries = [dict(**asdict(rule), revision=revision) for rule, revision in rows]
    entries.sort(key=lambda value: (value['path'], value['subject_type'],
                                   value['namespace'], value['external_id']))
    payload = json.dumps(entries, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':')).encode('utf-8')
    return sha256(payload).hexdigest()


def serialize(rows):
    entries = [dict(**asdict(rule), revision=revision) for rule, revision in rows]
    return sorted(entries, key=lambda value: (value['path'], value['subject_type'],
                                               value['namespace'], value['external_id']))
