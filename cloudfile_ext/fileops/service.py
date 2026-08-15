# -*- coding: utf-8 -*-
"""Copy/move precheck orchestration and task submission (P2-06).

This is the Django/Seafile half of the capability; the pure decision logic it
depends on lives in ``policy.py`` so it stays unit-testable on its own. The
flow a view follows is::

    evaluation = evaluate(request, operation, payload)   # raises PrecheckError
    if not evaluation['to_run']:
        return failures_only(evaluation)
    result = submit(request, operation, evaluation)

``evaluate`` performs the whole-request checks (permission, cross-space, cyclic
move, batch limits, quota) and splits the requested items into ``to_run`` and
``failures``. ``submit`` is where idempotency lives: the idempotency key is
claimed *before* ``seafile_api.copy_file``/``move_file`` is called, so a
duplicate submission returns the first task instead of copying twice.
"""

import json
import logging
import posixpath
import stat
import uuid

from seahub.utils.repo import (
    get_repo_owner, get_repo_shared_users,
)
from seahub.views import check_folder_permission
from seahub.share.utils import is_repo_admin

from seaserv import seafile_api

from cloudfile_ext.fileops import policy
from cloudfile_ext.fileops.models import (
    FileOpTask, STATUS_RUNNING, STATUS_SUCCEEDED, STATUS_PARTIAL, STATUS_FAILED,
    OPERATION_COPY, OPERATION_MOVE,
)

logger = logging.getLogger(__name__)


class PrecheckError(Exception):
    """A whole-request rejection; carries the HTTP status to surface."""

    def __init__(self, http_status, message, reason=None):
        super(PrecheckError, self).__init__(message)
        self.http_status = http_status
        self.reason = reason


def _limits():
    """Return the configured limits as ints (0 = unlimited)."""
    from django.conf import settings

    def _int(name):
        try:
            return max(0, int(getattr(settings, name, 0) or 0))
        except (TypeError, ValueError):
            return 0

    return {
        'max_file_size': _int('CF_FILEOP_MAX_FILE_SIZE'),
        'max_folder_depth': _int('CF_FILEOP_MAX_FOLDER_DEPTH'),
        'max_item_count': _int('CF_FILEOP_MAX_ITEM_COUNT'),
        'max_batch_size': _int('CF_FILEOP_MAX_BATCH_SIZE'),
    }


def _source_names(payload):
    """Normalise the single-item and batch payload shapes into a list."""
    if payload.get('src_dirents'):
        return [n for n in payload['src_dirents'] if n]
    if payload.get('src_dirent_name'):
        return [payload['src_dirent_name']]
    return []


def idempotency_key(username, operation, payload):
    """The idempotency key for a raw payload, computable without touching the tree.

    This is what the view consults *before* running the precheck: a completed
    move has already removed its source, so re-checking existence would report
    "not found" for what is really a duplicate click. The key only needs the
    raw request fields, which is why it lives apart from ``evaluate``.
    """
    return policy.build_idempotency_key(
        username, operation,
        payload.get('src_repo_id'),
        payload.get('src_parent_dir') or '/',
        _source_names(payload),
        payload.get('dst_repo_id'),
        payload.get('dst_parent_dir') or '/')


def lookup_cached(username, key):
    """Return the cached result for a previously-seen intent, or None.

    A ``failed`` task is treated as absent: retrying a failure is a new attempt,
    not a duplicate. Everything else (running / succeeded / partial) is returned
    as-is, which is what makes the second click a no-op.
    """
    task = FileOpTask.objects.find_by_key(username, key)
    if task is None or task.status == STATUS_FAILED:
        return None
    detail = {}
    try:
        if task.detail:
            detail = json.loads(task.detail)
    except ValueError:
        detail = {}
    return {
        'task_id': task.task_id,
        'done': task.status != STATUS_RUNNING,
        'failures': detail.get('failures', []),
        'affected_members': detail.get('affected_members'),
    }


def _measure_file(repo, file_id):
    return seafile_api.get_file_size(repo.store_id, repo.version, file_id)


def _measure_dir_depth(repo_id, path, guard=256):
    """Max folder depth below ``path`` (0 for a leaf directory).

    ``guard`` bounds the walk so a pathological tree cannot loop forever; a
    real Seafile tree has no cycles, so exceeding it only happens on corruption
    and is treated as "too deep" by the caller's depth limit.
    """
    if guard <= 0:
        return 0
    entries = seafile_api.list_dir_by_path(repo_id, path) or []
    deepest = 0
    for entry in entries:
        # `stat.S_ISDIR(entry.mode)` is the reliable directory test here;
        # Dirent.is_dir is not set on this seafile version's Dirent objects.
        if stat.S_ISDIR(entry.mode):
            child_depth = 1 + _measure_dir_depth(
                repo_id, posixpath.join(path, entry.obj_name), guard - 1)
            deepest = max(deepest, child_depth)
    return deepest


def _can_read(perm):
    return perm in ('r', 'rw', 'admin')


def _affected_members(request, src_repo_id, src_parent_dir, dst_repo_id,
                      dst_parent_dir):
    """How many members lose read access after a move (permission inheritance).

    The review checklist requires the move confirmation to warn about members
    who would lose access because the item inherits the destination's ACL. We
    compare, for every member of the source library, their effective permission
    on the source parent against the destination parent. ``check_permission_by_path``
    is the C authority, so directory ACL and repo share are both reflected.
    """
    src_owner = get_repo_owner(request, src_repo_id)
    if not src_owner:
        return 0
    members = get_repo_shared_users(src_repo_id, src_owner, include_groups=True)
    affected = 0
    for username in members:
        try:
            src_perm = seafile_api.check_permission_by_path(
                src_repo_id, src_parent_dir, username)
            dst_perm = seafile_api.check_permission_by_path(
                dst_repo_id, dst_parent_dir, username)
        except Exception:
            # A member lookup must never veto a move the operator is entitled
            # to make; a failed count is just a weaker warning.
            logger.exception('affected-member lookup failed for %s', username)
            continue
        if _can_read(src_perm) and not _can_read(dst_perm):
            affected += 1
    return affected


def evaluate(request, operation, payload):
    """Run the unified precheck. Returns an evaluation dict; raises on 4xx.

    ``payload`` keys: src_repo_id, src_parent_dir, src_dirent_name or
    src_dirents, dst_repo_id, dst_parent_dir, dirent_type, conflict_policy
    (optional).
    """
    username = request.user.username
    src_repo_id = payload.get('src_repo_id')
    src_parent_dir = payload.get('src_parent_dir') or '/'
    dst_repo_id = payload.get('dst_repo_id')
    dst_parent_dir = payload.get('dst_parent_dir') or '/'
    dirent_type = (payload.get('dirent_type') or 'file').lower()
    conflict_policy = payload.get('conflict_policy') or \
        policy.DEFAULT_CONFLICT_POLICY
    src_names = _source_names(payload)

    if not src_repo_id or not dst_repo_id:
        raise PrecheckError(400, 'src_repo_id and dst_repo_id are required.')
    if not src_names:
        raise PrecheckError(400, 'src_dirent_name or src_dirents is required.')
    if conflict_policy not in policy.CONFLICT_POLICIES:
        raise PrecheckError(400, 'conflict_policy must be one of %s'
                            % ', '.join(policy.CONFLICT_POLICIES))
    if operation not in (OPERATION_COPY, OPERATION_MOVE):
        raise PrecheckError(400, "operation can only be 'copy' or 'move'.")

    src_repo = seafile_api.get_repo(src_repo_id)
    if not src_repo:
        raise PrecheckError(404, 'Library %s not found.' % src_repo_id)
    dst_repo = seafile_api.get_repo(dst_repo_id)
    if not dst_repo:
        raise PrecheckError(404, 'Library %s not found.' % dst_repo_id)
    if not seafile_api.get_dir_id_by_path(src_repo_id, src_parent_dir):
        raise PrecheckError(404, 'Folder %s not found.' % src_parent_dir)
    if not seafile_api.get_dir_id_by_path(dst_repo_id, dst_parent_dir):
        raise PrecheckError(404, 'Folder %s not found.' % dst_parent_dir)

    src_owner = get_repo_owner(request, src_repo_id)
    dst_owner = get_repo_owner(request, dst_repo_id)
    cross_owner = bool(src_owner and dst_owner and src_owner != dst_owner)

    source_perm = check_folder_permission(request, src_repo_id, src_parent_dir)
    target_perm = check_folder_permission(request, dst_repo_id, dst_parent_dir)
    source_admin = is_repo_admin(username, src_repo_id)

    reason = policy.check_permissions(operation, source_perm, target_perm,
                                      cross_owner, source_admin)
    if reason == policy.REASON_PERMISSION:
        raise PrecheckError(403, 'Permission denied.', reason=reason)
    if reason == policy.REASON_CROSS_SPACE:
        raise PrecheckError(403, 'Moving out of another space requires admin.',
                            reason=reason)

    # Cyclic / degenerate move, checked before any per-item work.
    if operation == OPERATION_MOVE and len(src_names) == 1 and \
            dirent_type == 'dir':
        if policy.check_move_cycle(src_parent_dir, src_names[0], dst_parent_dir,
                                   src_repo_id, dst_repo_id):
            raise PrecheckError(400, 'Can not move folder into itself.',
                                reason=policy.REASON_CYCLIC)

    limits = _limits()
    if policy.check_item_count(len(src_names), limits['max_item_count']):
        raise PrecheckError(400, 'Too many items in one batch.',
                            reason=policy.REASON_OVER_COUNT)

    dst_entries = seafile_api.list_dir_by_path(dst_repo_id, dst_parent_dir) or []
    existing_names = {e.obj_name for e in dst_entries}

    to_run = []
    failures = []
    total_size = 0

    for name in src_names:
        src_path = posixpath.join(src_parent_dir, name)
        file_id = seafile_api.get_file_id_by_path(src_repo_id, src_path)
        dir_id = seafile_api.get_dir_id_by_path(src_repo_id, src_path)
        if not file_id and not dir_id:
            failures.append({'name': name, 'reason': policy.REASON_NOT_FOUND})
            continue

        if file_id:
            size = _measure_file(src_repo, file_id)
            # Destination capacity beats the per-file size policy: a copy that
            # would exceed the destination quota is a quota error (443),
            # review copy-006. Same-owner moves write nothing, so skip them.
            if (operation == OPERATION_COPY or cross_owner) and \
                    seafile_api.check_quota(dst_repo_id, size) < 0:
                raise PrecheckError(443, 'Out of quota.',
                                    reason=policy.REASON_OVER_QUOTA)
            if policy.check_single_file_size(size, limits['max_file_size']):
                failures.append({'name': name,
                                 'reason': policy.REASON_OVER_SIZE})
                continue
        else:
            if policy.check_folder_depth(
                    _measure_dir_depth(src_repo_id, src_path),
                    limits['max_folder_depth']):
                failures.append({'name': name,
                                 'reason': policy.REASON_OVER_DEPTH})
                continue
            size = seafile_api.get_dir_size(src_repo.store_id, src_repo.version,
                                            dir_id)

        new_name = policy.resolve_conflict(name, existing_names,
                                           conflict_policy)
        if new_name is None:
            failures.append({'name': name,
                             'reason': policy.REASON_NAME_CONFLICT})
            continue
        if new_name != name:
            existing_names.add(new_name)

        total_size += size
        to_run.append({'name': name, 'new_name': new_name, 'size': size})

    if policy.check_batch_size(total_size, limits['max_batch_size']):
        raise PrecheckError(400, 'Batch is too large.',
                            reason=policy.REASON_OVER_BATCH_SIZE)

    # Quota applies to content that actually lands in the destination: copy
    # always writes; a same-owner move writes nothing new, so skip it.
    if to_run and (operation == OPERATION_COPY or cross_owner):
        if seafile_api.check_quota(dst_repo_id, total_size) < 0:
            raise PrecheckError(443, 'Out of quota.',
                                reason=policy.REASON_OVER_QUOTA)

    idempotency_key = policy.build_idempotency_key(
        username, operation, src_repo_id, src_parent_dir, src_names,
        dst_repo_id, dst_parent_dir)

    return {
        'username': username,
        'idempotency_key': idempotency_key,
        'operation': operation,
        'src_repo_id': src_repo_id,
        'src_parent_dir': src_parent_dir,
        'dst_repo_id': dst_repo_id,
        'dst_parent_dir': dst_parent_dir,
        'conflict_policy': conflict_policy,
        'to_run': to_run,
        'failures': failures,
        'affected_members': (_affected_members(
            request, src_repo_id, src_parent_dir, dst_repo_id, dst_parent_dir)
            if operation == OPERATION_MOVE else None),
    }


def failures_only(evaluation):
    """Response shape when every item failed precheck: no task is created."""
    return {
        'done': True,
        'failures': evaluation['failures'],
        'affected_members': evaluation['affected_members'],
    }


def submit(request, operation, evaluation):
    """Claim the idempotency key, run the operation, and report.

    The claim happens before the seafile_api call; a duplicate submission finds
    the existing task and returns it without touching the tree, which is the
    "repeated click does not make a second copy" acceptance criterion.
    """
    username = evaluation['username']
    task_id = str(uuid.uuid4())
    task, created = FileOpTask.objects.claim(
        username, evaluation['idempotency_key'], operation, task_id)

    if not created:
        return {
            'task_id': task.task_id,
            'done': task.status != STATUS_RUNNING,
            'failures': evaluation['failures'],
            'affected_members': evaluation['affected_members'],
        }

    src_names = [item['name'] for item in evaluation['to_run']]
    dst_names = [item['new_name'] for item in evaluation['to_run']]

    try:
        if operation == OPERATION_COPY:
            res = seafile_api.copy_file(
                evaluation['src_repo_id'], evaluation['src_parent_dir'],
                json.dumps(src_names), evaluation['dst_repo_id'],
                evaluation['dst_parent_dir'], json.dumps(dst_names),
                username=username, need_progress=1)
        else:
            res = seafile_api.move_file(
                evaluation['src_repo_id'], evaluation['src_parent_dir'],
                json.dumps(src_names), evaluation['dst_repo_id'],
                evaluation['dst_parent_dir'], json.dumps(dst_names),
                replace=evaluation['conflict_policy'] == policy.CONFLICT_OVERWRITE,
                username=username, need_progress=1)
    except Exception as exc:
        logger.exception('fileop %s failed', operation)
        FileOpTask.objects.mark(task, STATUS_FAILED, str(exc))
        raise

    if not res:
        FileOpTask.objects.mark(task, STATUS_FAILED, 'seafile_api returned false')
        return {
            'task_id': task.task_id,
            'done': True,
            'failed': True,
            'failures': evaluation['failures'],
            'affected_members': evaluation['affected_members'],
        }

    if res.background:
        # The seafile-server copy/move task runs on; cf_fileop_task is a dedup
        # record, not a progress tracker (res.task_id is that handle), so keep
        # it "running" rather than claiming success that has not happened yet.
        status = STATUS_RUNNING
    else:
        status = STATUS_PARTIAL if evaluation['failures'] else STATUS_SUCCEEDED
    FileOpTask.objects.mark(task, status, json.dumps({
        'failures': evaluation['failures'],
        'affected_members': evaluation['affected_members'],
    }))

    result = {
        'task_id': task.task_id,
        'done': not res.background,
        'failures': evaluation['failures'],
        'affected_members': evaluation['affected_members'],
    }
    if res.background:
        # The seafile-server task id is the progress handle; cf_fileop_task's
        # task_id stays keyed to this intent so a duplicate sees the same value.
        result['progress_task_id'] = res.task_id
    return result
