# -*- coding: utf-8 -*-
"""System-admin endpoints: register sources and grant access to them.

Admin-only, with no library-ownership path: an external source has no owner.
That is also why these use ``IsAdminUser`` rather than anything derived from
``check_folder_permission`` -- see the note in AGENTS.md about a capability's
own management API locking its administrator out through its own rules.
"""

import logging
import time

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext import identity
from cloudfile_ext.features import is_enabled
from cloudfile_ext.external_sources import paths, service
from cloudfile_ext.external_sources.models import (
    ExternalOverlay, ExternalScanState, ExternalSource, ExternalSourceGrant,
    PERMISSION_R, SUBJECT_GROUP, SUBJECT_USER, VALID_PERMISSIONS,
    VALID_SUBJECT_TYPES,
)

logger = logging.getLogger(__name__)


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND,
                     'External sources are not enabled.')


def _allowed_roots():
    from django.conf import settings

    return getattr(settings, 'CF_EXTERNAL_SOURCES_ROOTS',
                   paths.DEFAULT_ROOTS) or paths.DEFAULT_ROOTS


class AdminExternalSourcesView(APIView):
    """List every registered source, or register one."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        sources = ExternalSource.objects.all().order_by('name')
        return Response({
            'sources': [self._serialize(s) for s in sources],
            'allowed_roots': list(_allowed_roots()),
        })

    def post(self, request):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        from cloudfile_ext.registry import registry

        name = (request.data.get('name') or '').strip()
        source_type = (request.data.get('source_type') or '').strip()
        root_path = (request.data.get('root_path') or '').strip()

        if not name:
            return api_error(status.HTTP_400_BAD_REQUEST, 'name is required.')
        if source_type not in registry.external_sources:
            return api_error(
                status.HTTP_400_BAD_REQUEST,
                'source_type invalid; registered types: %s'
                % (', '.join(sorted(registry.external_sources)) or 'none'))

        # Containment is checked here *and* on every access. Doing it here is
        # for the administrator's benefit -- a misconfigured root should fail
        # while they are looking at the form, not silently later.
        try:
            paths.check_root_allowed(root_path, _allowed_roots())
        except paths.UnsafePath as exc:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'root_path invalid: %s' % exc)

        if ExternalSource.objects.filter(name=name).exists():
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'a source named %s already exists.' % name)

        try:
            source = ExternalSource.objects.create_source(
                name, source_type, paths.normalize_root(root_path))
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        return Response(self._serialize(source))

    def _serialize(self, source):
        info = service.serialize_source(source)
        # Only the admin listing exposes root_path: it is a container
        # filesystem path, and users browsing a source have no use for it.
        info['root_path'] = source.root_path
        return info


class AdminExternalSourceView(APIView):
    """Enable, disable, rename or delete one source."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def put(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        source = ExternalSource.objects.filter(id=source_id).first()
        if source is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')

        if 'name' in request.data:
            name = (request.data.get('name') or '').strip()
            if not name:
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name is required.')
            if ExternalSource.objects.filter(name=name).exclude(
                    id=source.id).exists():
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'a source named %s already exists.' % name)
            source.name = name

        if 'root_path' in request.data:
            root_path = (request.data.get('root_path') or '').strip()
            try:
                paths.check_root_allowed(root_path, _allowed_roots())
            except paths.UnsafePath as exc:
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'root_path invalid: %s' % exc)
            source.root_path = paths.normalize_root(root_path)

        if 'enabled' in request.data:
            source.enabled = 1 if request.data.get('enabled') else 0

        source.mtime = int(time.time())
        try:
            source.save()
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        info = service.serialize_source(source)
        info['root_path'] = source.root_path
        return Response(info)

    def delete(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        source = ExternalSource.objects.filter(id=source_id).first()
        if source is None:
            # Idempotent: re-deleting is success, so a retried request after a
            # dropped response does not read as a failure.
            return Response({'success': True})

        try:
            # Grants first: a source row that is gone with grants left behind
            # would silently re-authorise whoever had access if the same id is
            # ever reused by AUTO_INCREMENT after a restore.
            ExternalSourceGrant.objects.filter(source_id=source.id).delete()
            ExternalOverlay.objects.filter(source_id=source.id).delete()
            ExternalScanState.objects.filter(source_id=source.id).delete()
            repo_id = source.repo_id
            source.delete()
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        # Meilisearch is deliberately outside the database transaction. A
        # search outage must not make a source impossible to decommission;
        # authorization still filters any stale document, and the next index
        # maintenance run can remove it. Normal removal is immediate.
        try:
            from django.conf import settings
            if getattr(settings, 'CF_PROVIDER_SEARCH', '') == 'meilisearch':
                from cloudfile_ext.search.backends.meilisearch import client_from_settings
                client_from_settings().delete_by_repo(repo_id)
        except Exception:
            logger.warning('could not remove external search documents for %s',
                           repo_id, exc_info=True)

        return Response({'success': True})


class AdminExternalSourceGrantsView(APIView):
    """List, add or remove who may read a source."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        source = ExternalSource.objects.filter(id=source_id).first()
        if source is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')

        grants = ExternalSourceGrant.objects.for_source(source.id)
        return Response({
            'source_id': source.id,
            'grants': [{
                'subject_type': g.subject_type,
                'subject': g.subject,
                'permission': g.permission,
                'ctime': g.ctime,
            } for g in grants],
        })

    def post(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        source = ExternalSource.objects.filter(id=source_id).first()
        if source is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')

        subject_type = request.data.get('subject_type', '')
        subject = request.data.get('subject', '')
        permission = request.data.get('permission', PERMISSION_R)

        error, subject = self._resolve(subject_type, subject, permission)
        if error:
            return error

        try:
            grant = ExternalSourceGrant.objects.grant(
                source.id, subject_type, subject, permission)
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        return Response({
            'subject_type': grant.subject_type,
            'subject': grant.subject,
            'permission': grant.permission,
            'ctime': grant.ctime,
        })

    def delete(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        error, subject = self._resolve(subject_type, subject, PERMISSION_R)
        if error:
            return error

        try:
            ExternalSourceGrant.objects.revoke(source_id, subject_type, subject)
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        return Response({'success': True})

    def _resolve(self, subject_type, subject, permission):
        """Validate a subject and map it to what enforcement compares against.

        Returns ``(error_response_or_None, resolved_subject)``.

        Resolution is not cosmetic. Seafile 14 separated identity from email:
        an account's primary key is ``<hex>@auth.local`` and the email address
        is a login attribute. A grant stored by email never matches, and it
        fails silently -- the API returns 200, nothing is logged, and an
        administrator is left believing they granted access. That exact bug
        shipped twice in the ACL capability (FEATURES.md item 71), which is why
        this resolves *before* writing and refuses when it cannot.
        """
        if subject_type not in VALID_SUBJECT_TYPES:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type must be one of: %s'
                             % ', '.join(VALID_SUBJECT_TYPES)), subject
        if not subject:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject is required.'), subject
        if permission not in VALID_PERMISSIONS:
            return api_error(
                status.HTTP_400_BAD_REQUEST,
                'permission must be one of: %s (external sources are '
                'read-only in this release)'
                % ', '.join(VALID_PERMISSIONS)), subject

        try:
            if subject_type == SUBJECT_USER:
                subject = identity.resolve_user(subject)
            elif subject_type == SUBJECT_GROUP:
                subject = identity.resolve_group(subject)
        except identity.UnknownSubject as exc:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % exc), subject

        return None, subject
