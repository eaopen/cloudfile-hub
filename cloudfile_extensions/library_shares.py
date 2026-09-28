"""Small, ledger-owned library share reconciler for the eTech creation path."""
import logging
import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pymysql
from django.conf import settings
from rest_framework.response import Response

from seaserv import seafile_api
from seahub.api2.utils import api_error
from seahub.api2.endpoints.admin.library_administrator import AdminLibraryAdministrator
from .library_share_plan import plan as build_share_plan
from .events.outbox import EventWriter

logger = logging.getLogger(__name__)


def _database():
    config = getattr(settings, 'CLOUDFILE_POLICY_CONFIG', None)
    if not isinstance(config, dict) or not isinstance(config.get('database'), dict):
        raise ValueError('Policy database is not configured')
    item = config['database']
    return pymysql.connect(host=item['host'], port=item.get('port', 3306), user=item['user'],
                           password=item['password'], database=item['name'], charset='utf8mb4',
                           connect_timeout=3, read_timeout=10, write_timeout=10, autocommit=True)


class LibrarySharesDesired(AdminLibraryAdministrator):
    """Accept a bounded complete desired state; never revoke shares outside our ledger."""
    http_method_names = ('put',)

    def put(self, request, repo_id):
        if request.GET:
            return api_error(400, 'Query parameters are not supported.')
        try:
            if str(UUID(repo_id)) != repo_id or not isinstance(request.data, dict) or set(request.data) != {'policy_revision', 'shares'}:
                return api_error(400, 'Invalid desired-state request.')
        except (ValueError, TypeError):
            return api_error(400, 'Invalid library ID.')
        revision, shares = request.data['policy_revision'], request.data['shares']
        if type(revision) is not int or revision < 1 or revision > 9223372036854775807 or not isinstance(shares, list) or len(shares) > 1000:
            return api_error(400, 'Invalid revision or share count.')
        desired = {}
        for share in shares:
            if not isinstance(share, dict) or set(share) != {'external_group_id', 'permission'}:
                return api_error(400, 'Invalid share entry.')
            external_id, permission = share['external_group_id'], share['permission']
            if (not isinstance(external_id, str) or not re.fullmatch(r'[A-Za-z0-9:._-]{1,255}', external_id)
                    or external_id in desired or permission not in ('r', 'rw')):
                return api_error(400, 'Invalid or duplicate share target.')
            desired[external_id] = permission
        denied = self._authorize(request, repo_id)
        if denied is not None:
            return denied
        owner = seafile_api.get_repo_owner(repo_id) or seafile_api.get_org_repo_owner(repo_id)
        if not owner:
            return api_error(503, 'Library owner is unavailable.')
        config = getattr(settings, 'CLOUDFILE_POLICY_CONFIG', None)
        provider = config.get('provider') if isinstance(config, dict) else None
        if not isinstance(provider, str) or not provider:
            return api_error(503, 'Directory provider is unavailable.')
        connection = None
        locked = False
        try:
            connection = _database()
            with connection.cursor() as cursor:
                cursor.execute("SELECT GET_LOCK(CONCAT('cf.share.',%s),5)", (repo_id,))
                locked = cursor.fetchone() == (1,)
                if not locked:
                    return api_error(503, 'Library share reconciliation is busy.')
                cursor.execute('SELECT revision FROM cf_library_share_revision WHERE repo_id=%s', (repo_id,))
                previous = cursor.fetchone()
                if previous and revision < previous[0]:
                    return api_error(409, 'Stale library share revision.')
                share_plan, errors = build_share_plan(cursor, repo_id, provider, desired)
                unmapped = len(errors)
                applied = {'add': 0, 'update': 0, 'revoke': 0}
                writer = EventWriter()
                # Native shares and policy SQL are separate stores. An add intent is
                # persisted before the RPC, so retry can distinguish our partial add
                # from a pre-existing manual share without adopting that share.
                for operation in ('add', 'update', 'revoke'):
                    for external_id, group_id, permission in share_plan[operation]:
                        try:
                            if operation == 'revoke':
                                seafile_api.unset_group_repo(repo_id, group_id, owner)
                            else:
                                if operation == 'add':
                                    is_org = bool(seafile_api.get_org_repo_owner(repo_id))
                                    native = seafile_api.get_group_shared_repo_by_path(repo_id, None, group_id, is_org)
                                    cursor.execute('SELECT group_id,permission,state FROM cf_library_share_ledger WHERE repo_id=%s AND external_id=%s',
                                                   (repo_id, external_id))
                                    pending = cursor.fetchone()
                                    if pending and pending[2] == 'PENDING':
                                        if pending[:2] != (group_id, permission):
                                            raise ValueError('pending share intent differs from desired state')
                                        if native and native.permission != permission:
                                            raise ValueError('pending native share differs from desired state')
                                    else:
                                        if native:
                                            raise ValueError('native group share already exists outside the managed ledger')
                                        cursor.execute("INSERT INTO cf_library_share_ledger(repo_id,external_id,group_id,permission,state,updated_at) VALUES(%s,%s,%s,%s,'PENDING',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE group_id=VALUES(group_id),permission=VALUES(permission),state='PENDING',updated_at=VALUES(updated_at)",
                                                       (repo_id, external_id, group_id, permission))
                                    if not native:
                                        seafile_api.set_group_repo(repo_id, group_id, owner, permission)
                                else:
                                    seafile_api.set_group_repo(repo_id, group_id, owner, permission)
                            # SQL status and its CloudFile audit fact commit together.
                            # If this fails after the native RPC, the ledger remains
                            # retryable (PENDING or APPLIED) instead of claiming success.
                            connection.begin()
                            try:
                                if operation == 'revoke':
                                    cursor.execute("UPDATE cf_library_share_ledger SET state='REVOKED',updated_at=UTC_TIMESTAMP(6) WHERE repo_id=%s AND external_id=%s",
                                                   (repo_id, external_id))
                                else:
                                    cursor.execute("INSERT INTO cf_library_share_ledger(repo_id,external_id,group_id,permission,state,updated_at) VALUES(%s,%s,%s,%s,'APPLIED',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE group_id=VALUES(group_id),permission=VALUES(permission),state='APPLIED',updated_at=VALUES(updated_at)",
                                                   (repo_id, external_id, group_id, permission))
                                writer.append(cursor, dict(event_id=str(uuid4()), request_id=str(uuid4()),
                                    occurred_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                                    actor_user_id=request.user.username, actor_kind='user', source='hub',
                                    action='library.share.' + ('revoked' if operation == 'revoke' else 'updated' if operation == 'update' else 'added'),
                                    result='succeeded', repo_id=repo_id, path='/', resource_kind='dir',
                                    reason='external_group_id=' + external_id + ';permission=' + (permission or 'none')))
                                connection.commit()
                            except Exception:
                                connection.rollback()
                                raise
                            applied[operation] += 1
                        except Exception:
                            logger.exception('Library share operation failed: %s %s', operation, external_id)
                            errors.append(operation + ' ' + external_id + ': native share update failed')
                cursor.execute('INSERT INTO cf_library_share_revision(repo_id,revision) VALUES(%s,%s) ON DUPLICATE KEY UPDATE revision=GREATEST(revision,VALUES(revision))',
                               (repo_id, revision))
                result = {'revision': revision, 'revision_recorded': True,
                          'planned': {key: len(value) + (unmapped if key == 'add' else 0)
                                      for key, value in share_plan.items()},
                          'applied': applied, 'errors': errors}
                response = Response(result)
                response['Cache-Control'] = 'no-store'
                return response
        except Exception:
            logger.exception('Library share reconciliation failed')
            return api_error(503, 'Library share reconciliation is unavailable.')
        finally:
            if connection is not None:
                if locked:
                    try:
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT RELEASE_LOCK(CONCAT('cf.share.',%s))", (repo_id,))
                    except Exception:
                        logger.exception('Library share lock release failed')
                connection.close()
