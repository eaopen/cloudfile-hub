# _*_ coding:utf-8 _*_
import logging
from collections import defaultdict

from django.conf import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.repo_tags.models import RepoTags
from seahub.file_tags.models import FileTags
from seahub.api2.utils import api_error, to_python_boolean
from seahub.views import check_folder_permission
from seahub.constants import PERMISSION_READ_WRITE, PERMISSION_ADMIN
from seahub.share.utils import is_repo_admin

from seaserv import seafile_api

logger = logging.getLogger(__name__)


# CloudFile P2-07: repo tags grow a system/user classification (docs/roles-semantics.md §6).
# System tags are admin-managed and read-only for everyone else; user tags are
# editable by rw and above. Everything below is gated on CF_ENABLE_TAGS so that
# with the switch off the endpoint behaves exactly like native CE.
DEFAULT_TAG_BATCH_LIMIT = 100


def _cf_tags_enabled():
    try:
        from cloudfile_ext.features import is_enabled
        return is_enabled('CF_ENABLE_TAGS')
    except ImportError:
        return False


def _parse_is_system(value):
    if value is None or isinstance(value, bool):
        return bool(value)
    try:
        return to_python_boolean(value)
    except ValueError:
        return False


def _batch_limit():
    return getattr(settings, 'CF_TAG_BATCH_LIMIT', DEFAULT_TAG_BATCH_LIMIT)


def _can_write_tag(request, repo_id, is_system):
    """Authorize a tag write.

    With CF_ENABLE_TAGS on, system tags are admin-only and user tags need rw or
    above. With it off, native CE behaviour is preserved: any write requires
    exactly rw, and a system tag can never be created (fail closed).
    """
    if is_system:
        return _cf_tags_enabled() and is_repo_admin(request.user.username, repo_id)

    perm = check_folder_permission(request, repo_id, '/')
    if _cf_tags_enabled():
        return perm in (PERMISSION_READ_WRITE, PERMISSION_ADMIN)
    return perm == PERMISSION_READ_WRITE


class RepoTagsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        """list all repo_tags by repo_id.
        """
        # argument check
        include_file_count = request.GET.get('include_file_count', 'true')
        if include_file_count not in ['true', 'false']:
            error_msg = 'include_file_count invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        include_file_count = to_python_boolean(include_file_count)

        # resource check
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, '/'):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # get files tags
        files_count = defaultdict(int)
        if include_file_count:
            try:
                files_tags = FileTags.objects.select_related('repo_tag').filter(repo_tag__repo_id=repo_id)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
            for file_tag in files_tags:
                files_count[file_tag.repo_tag_id] += 1

        repo_tags = []
        try:
            # P2-07: user tags (is_system=false) sort before system tags
            # (is_system=true); within each group keep insertion order.
            repo_tag_list = RepoTags.objects.get_all_by_repo_id(repo_id).order_by('is_system', 'id')
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        for repo_tag in repo_tag_list:
            res = repo_tag.to_dict()
            repo_tag_id = res["repo_tag_id"]
            if repo_tag_id in files_count:
                res["files_count"] = files_count[repo_tag_id]
            else:
                res["files_count"] = 0
            repo_tags.append(res)

        return Response({"repo_tags": repo_tags}, status=status.HTTP_200_OK)

    def post(self, request, repo_id):
        """add one repo_tag.
        """
        # argument check
        tag_name = request.data.get('name')
        if not tag_name:
            error_msg = 'name invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        tag_color = request.data.get('color')
        if not tag_color:
            error_msg = 'color invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        is_system = _cf_tags_enabled() and _parse_is_system(request.data.get('is_system'))

        # resource check
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        repo_tag = RepoTags.objects.get_repo_tag_by_name(repo_id, tag_name)
        if repo_tag:
            error_msg = 'repo tag %s already exist.' % tag_name
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # permission check
        if not _can_write_tag(request, repo_id, is_system):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            repo_tag = RepoTags.objects.create_repo_tag(repo_id, tag_name, tag_color, is_system)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({"repo_tag": repo_tag.to_dict()}, status=status.HTTP_201_CREATED)

    def put(self, request, repo_id):
        """bulk add repo_tags.
        """

        # argument check
        tags = request.data.get('tags')
        if not tags:
            error_msg = 'tags invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # P2-07: batch add honours a single-request upper limit.
        if _cf_tags_enabled() and len(tags) > _batch_limit():
            error_msg = 'Number of tags exceeds the limit of %s.' % _batch_limit()
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # permission check: a batch containing a system tag requires admin;
        # otherwise rw (or admin) suffices.
        any_system = _cf_tags_enabled() and any(_parse_is_system(tag.get('is_system')) for tag in tags)
        if not _can_write_tag(request, repo_id, any_system):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        tag_objs = list()
        try:
            for tag in tags:
                name = tag.get('name' ,'')
                color = tag.get('color', '')
                is_system = _cf_tags_enabled() and _parse_is_system(tag.get('is_system'))
                if name and color:
                    obj = RepoTags(repo_id=repo_id, name=name, color=color, is_system=is_system)
                    tag_objs.append(obj)
        except Exception as e:
            logger.error(e)
            error_msg = 'tags invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            repo_tag_list = RepoTags.objects.bulk_create(tag_objs)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        repo_tags = list()
        for repo_tag in repo_tag_list:
            res = repo_tag.to_dict()
            repo_tags.append(res)

        return Response({"repo_tags": repo_tags}, status=status.HTTP_200_OK)


class RepoTagView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def put(self, request, repo_id, repo_tag_id):
        """update one repo_tag
        """
        # argument check
        tag_name = request.data.get('name')
        if not tag_name:
            error_msg = 'name invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        tag_color = request.data.get('color')
        if not tag_color:
            error_msg = 'color invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo_tag = RepoTags.objects.get_repo_tag_by_id(repo_tag_id)
        if not repo_tag:
            error_msg = 'repo_tag not found.'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not _can_write_tag(request, repo_id, repo_tag.is_system):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            repo_tag.name = tag_name
            repo_tag.color = tag_color
            repo_tag.save()
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({"repo_tag": repo_tag.to_dict()}, status=status.HTTP_200_OK)

    def delete(self, request, repo_id, repo_tag_id):
        """delete one repo_tag
        """
        # resource check
        repo_tag = RepoTags.objects.get_repo_tag_by_id(repo_tag_id)
        if not repo_tag:
            error_msg = 'repo_tag not found.'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not _can_write_tag(request, repo_id, repo_tag.is_system):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            RepoTags.objects.delete_repo_tag(repo_tag_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({"success": "true"}, status=status.HTTP_200_OK)
