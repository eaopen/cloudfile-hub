"""Offline, restartable conversion from independent shares to unified ACLs.

The legacy table is dropped only after conversion commits. Never modify old
migration definitions: deployed ledgers validate their original checksums.
"""
from uuid import UUID, uuid4

from .runner import MigrationError


def merge_shares(runner):
    from ..authorization.rules import ACLRules, digest
    from ..authorization.shares import share_value
    from ..common.validation import identifier
    connection = runner.connection
    connection.begin()
    try:
        enroll = runner._query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_managed_library'")[0][0]
        after = ''
        with connection.cursor() as cursor:
            while True:
                cursor.execute('SELECT id,repo_id,path,path_hash,lifecycle_ref,subject_type,provider,namespace,'
                    'external_id,subject_hash,revision,created_by FROM cf_dir_share WHERE id>%s ORDER BY id LIMIT 500 FOR UPDATE', (after,))
                batch = cursor.fetchall()
                if not batch:
                    break
                for id_, repo, path, hashed, birth, type_, provider, namespace, external, subject_hash, revision, actor in batch:
                    value = share_value(dict(path=path, subject=dict(type=type_, provider=provider,
                        namespace=namespace, external_id=external)))
                    if (any(str(UUID(v)) != v for v in (id_, repo, revision)) or path != value['path'] or
                            hashed != digest(path) or subject_hash != ACLRules._subject_hash(value['subject'])):
                        raise ValueError('invalid legacy share')
                    identifier(birth, maximum=512)
                    identifier(actor, maximum=225)
                    if enroll:
                        # Full-schema upgrades have already applied migration 032;
                        # converted share-only libraries must satisfy its invariant.
                        cursor.execute('INSERT INTO cf_managed_library(repo_id,created_at) VALUES(%s,UTC_TIMESTAMP(6)) '
                            'ON DUPLICATE KEY UPDATE repo_id=VALUES(repo_id)', (repo,))
                    cursor.execute('SELECT ' + ACLRules.FIELDS + ' FROM cf_dir_acl WHERE repo_id=%s AND path_hash=%s '
                        "AND kind='dir' AND subject_hash=%s FOR UPDATE", (repo, hashed, subject_hash))
                    rows = cursor.fetchall()
                    if rows:
                        current = ACLRules._decode(rows[0])
                        if len(rows) != 1 or current['path'] != path or current['subject'] != value['subject']:
                            raise ValueError('ambiguous legacy ACL')
                        if current['share_mode'] and current['lifecycle_ref'] != birth:
                            raise ValueError('conflicting lifecycle evidence')
                        if not current['share_mode']:
                            cursor.execute('UPDATE cf_dir_acl SET share_mode=1,lifecycle_ref=%s,revision=%s WHERE id=%s',
                                (birth, str(uuid4()), current['id']))
                    else:
                        # A duplicate ID for a different identity must abort, not
                        # use ON DUPLICATE KEY UPDATE to overwrite another grant.
                        fields = (id_, repo, path, hashed, 'dir', type_, provider, namespace,
                            external, subject_hash, 'r', 1, revision, 1, birth)
                        cursor.execute('INSERT INTO cf_dir_acl (' + ACLRules.FIELDS + ') VALUES (' +
                            ','.join(['%s'] * len(fields)) + ')', fields)
                after = batch[-1][0]
        connection.commit()
    except Exception:
        connection.rollback()
        raise MigrationError('legacy shares conflict or contain invalid facts; no share rows converted') from None


def successor_steps():
    from .runner import load_migrations
    return next(m.steps for m in load_migrations() if m.version == '042_unified_directory_acl')
