# -*- coding: utf-8 -*-
"""Pure directory-ACL resolution.

This module is the Python half of the spec in cloudfile-docker/docs/
acl-semantics.md. It is deliberately free of Django, database and Seafile
imports so that it can be exercised directly by the shared case set in
docs/acl-cases.json -- the same cases the C and Go implementations run.

Nothing here reads configuration or checks feature switches; callers do that.
"""

PERMISSION_RW = 'rw'
PERMISSION_R = 'r'
PERMISSION_NONE = 'none'
PERMISSION_INVISIBLE = 'invisible'

#: Rule permissions, ordered strictest first. See acl-semantics.md section 2.
PERMISSION_ORDER = {
    PERMISSION_INVISIBLE: 0,
    PERMISSION_NONE: 1,
    PERMISSION_R: 2,
    PERMISSION_RW: 3,
}

#: Permissions that deny outright, whatever the native permission is.
DENYING = (PERMISSION_INVISIBLE, PERMISSION_NONE)

#: Native permissions that sit on the same ordered chain as rule permissions.
COMPARABLE_NATIVE = (PERMISSION_R, PERMISSION_RW)

SUBJECT_USER = 'user'
SUBJECT_DEPT = 'dept'
SUBJECT_GROUP = 'group'

#: More specific subjects win outright over broader ones at the same level.
SUBJECT_PRECEDENCE = {
    SUBJECT_USER: 3,
    SUBJECT_DEPT: 2,
    SUBJECT_GROUP: 1,
}


def normalize_path(path):
    """Normalize a repo-relative path to its canonical form.

    Collapses separators, forces a leading slash and strips the trailing one.
    Deliberately does not touch case or Unicode composition: Seafile paths are
    byte-sensitive, and folding them here would let two distinct directories
    share one ACL entry.
    """
    if not path:
        return '/'
    parts = [p for p in path.split('/') if p]
    if not parts:
        return '/'
    return '/' + '/'.join(parts)


def path_hash(path):
    """sha1 of the normalized path, used as the indexable column."""
    import hashlib
    return hashlib.sha1(normalize_path(path).encode('utf-8')).hexdigest()


def ancestors(path):
    """Return every level from the root down to `path`, inclusive.

    ancestors('/a/b') == ['/', '/a', '/a/b']
    """
    path = normalize_path(path)
    if path == '/':
        return ['/']
    levels = ['/']
    current = ''
    for part in path.split('/')[1:]:
        current = current + '/' + part
        levels.append(current)
    return levels


def subject_set(username, group_ids=(), dept_ids=()):
    """Build the subject set for a user.

    `dept_ids` must already include ancestor departments -- a rule on
    /研发中心 applies to members of /研发中心/前端组. Expanding the hierarchy is
    the caller's job because it needs Seafile group data.
    """
    subjects = {(SUBJECT_USER, username)}
    subjects.update((SUBJECT_GROUP, str(gid)) for gid in group_ids)
    subjects.update((SUBJECT_DEPT, str(did)) for did in dept_ids)
    return subjects


def pick(rules):
    """Choose the winning permission among rules matching at one level.

    Two steps, per acl-semantics.md section 4.1: take the most specific
    subject type present, then take the strictest permission within it.

    Splitting by subject type first is what keeps an explicit user grant
    meaningful. Without it, one `r` rule on an "everyone" group would cap every
    individual `rw` grant in the repo, and an explicit grant could never take
    effect.
    """
    if not rules:
        return None
    best_type = max(SUBJECT_PRECEDENCE[r['subject_type']] for r in rules)
    candidates = [r for r in rules
                  if SUBJECT_PRECEDENCE[r['subject_type']] == best_type]
    return min((r['permission'] for r in candidates),
               key=lambda p: PERMISSION_ORDER[p])


def tighten(native, decision):
    """Combine a resolved rule with the native share permission.

    Security invariant: the result is never more privileged than `native`.
    """
    if decision in DENYING:
        return None

    if native in COMPARABLE_NATIVE:
        return min(native, decision, key=lambda p: PERMISSION_ORDER[p])

    if native == 'admin':
        # admin outranks everything on the chain, so the rule always wins.
        return decision

    # preview / cloud-edit / custom-* are not comparable with r and rw: one
    # allows viewing without download, the other editing without download.
    # Forcing them onto the chain would widen permission in some direction, so
    # they are only ever vetoed (handled above) and otherwise left alone.
    return native


def resolve(rules, subjects, path, native):
    """Resolve the effective permission for `path`.

    `rules` is an iterable of dicts with keys: path, subject_type, subject,
    permission, inherit. Paths are normalized here, so callers may pass raw
    values.

    Returns a permission string, or None for no access.
    """
    if native is None:
        # Nothing to tighten, and CloudFile must never widen.
        return None

    path = normalize_path(path)

    by_level = {}
    for rule in rules:
        if (rule['subject_type'], rule['subject']) not in subjects:
            continue
        by_level.setdefault(normalize_path(rule['path']), []).append(rule)

    decision = None
    for level in ancestors(path):
        applicable = [r for r in by_level.get(level, ())
                      if int(r.get('inherit', 1)) == 1 or level == path]
        if not applicable:
            # No rule at this level: keep inheriting the nearest ancestor's.
            continue
        decision = pick(applicable)

    if decision is None:
        return native
    return tighten(native, decision)
