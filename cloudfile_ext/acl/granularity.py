# -*- coding: utf-8 -*-
"""Authorisation granularity policy for the directory ACL.

Product decision (2026-09-12), recorded in cloudfile-docker/docs/acl-semantics.md:

* **Authorisation granularity is the folder.** ``r``/``rw`` may only be granted
  on the library root or a directory. Granting them on a *file* is refused,
  with guidance, because the underlying platform does not enforce file-level
  grants consistently: uploads / new versions / online-edit saves are decided
  on the *parent folder* (``seahub/api2/endpoints/file.py`` checks
  ``parent_dir``), so a file-level ``rw`` looks configured in the admin UI and
  silently does nothing at write time. Every hole of that shape we have
  debugged (a user "granted" rw on one file who still got 403) came from
  offering a granularity the enforcement points cannot honour uniformly.
* **Deny stays available on files.** ``invisible`` / ``none`` are vetoes that
  apply at every entry point regardless of native permission, and the read
  paths (list / download / preview / tags / search) already decide per object,
  so hiding one file is both meaningful and consistent.
* **A single person's access to a single file** is expressed as *move it into
  a dedicated folder and grant that folder*, or as a share link when the
  audience is outside the directory. Not as a file-level grant.

Kept Django-free so the shared checks (pytest only) can exercise the matrix
directly; the DB/RPC probes live in ``cloudfile_ext.acl.probes``.
"""

from cloudfile_ext.acl import resolver

KIND_ROOT = 'root'
KIND_DIR = 'dir'
KIND_FILE = 'file'

#: Permissions that *grant* something (as opposed to denying).
ALLOW_PERMISSIONS = (resolver.PERMISSION_R, resolver.PERMISSION_RW)

GRANT_ON_FILE_MESSAGE = (
    'Authorisation granularity is the folder: r/rw cannot be granted on a '
    'file. Move the file into a dedicated folder and grant that folder, or '
    'create a share link for an external audience. File-level rules are only '
    'accepted as deny (none / invisible).')

INELIGIBLE_MESSAGE = (
    'This subject has no permission on the library, so a path rule can never '
    'take effect (a rule refines access, it never creates it). Grant library '
    'access first, then narrow it with folder rules.')

INELIGIBLE_GROUP_MESSAGE = (
    'This group/department has no share on the library, so a path rule can '
    'never take effect. Share the library with the group (or one of its parent '
    'departments) first, then narrow it with folder rules.')


def check_grant(kind, permission):
    """Return a refusal message, or None when this rule may be stored.

    ``kind`` is one of KIND_ROOT / KIND_DIR / KIND_FILE (see
    ``probes.path_kind``); ``permission`` is one of the resolver permissions.
    """
    if permission in resolver.DENYING:
        # Denies are honest at any depth: they veto everywhere, and the read
        # paths already evaluate them per object.
        return None
    if kind == KIND_FILE:
        return GRANT_ON_FILE_MESSAGE
    return None


def check_eligibility(eligible, subject_type):
    """Return a refusal message when the subject cannot possibly be affected.

    ``eligible`` is True / False / None-unknown. Unknown must not block a write
    -- this is a usability guard, not a security control (the security control
    is ``resolve()`` refusing to invent access), and a probe that failed should
    not lock an administrator out of managing rules.
    """
    if eligible is not False:
        return None
    if subject_type == resolver.SUBJECT_USER:
        return INELIGIBLE_MESSAGE
    return INELIGIBLE_GROUP_MESSAGE


def annotate(rule, kind, eligible):
    """Add the report fields to a serialized rule.

    ``path_kind`` + ``eligible`` are what make the "configured but can never
    apply" class of rules visible instead of silent -- the report the admin
    surface needs after a support case like this one.
    """
    rule = dict(rule)
    rule['path_kind'] = kind
    rule['eligible'] = eligible
    rule['guidance'] = check_eligibility(eligible, rule.get('subject_type'))
    if kind == KIND_FILE and rule.get('permission') not in resolver.DENYING:
        rule['guidance'] = GRANT_ON_FILE_MESSAGE
    return rule
