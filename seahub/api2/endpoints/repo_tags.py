# _*_ coding:utf-8 _*_
import logging
from collections import defaultdict

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
from seahub.constants import PERMISSION_READ_WRITE

from seaserv import seafile_api
from cloudfile_ext.v2.acl_runtime import Authority
from cloudfile_ext.v2.acl_http import require_repo_manage
from cloudfile_ext.v2.tag_native import authorize_tag_label

logger = logging.getLogger(__name__)


def _native_tag_root_permission(request, repo_id, write=False):
    try:
        decision = Authority(request.user.username).effective(repo_id, '/')
        return decision.can_write if write else decision.can_read
    except Exception:
        logger.exception('Native CE repo-tag permission unavailable')
        return False


class RepoTagsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        """list all repo_tags by repo_id.
        """
        # argument check
        include_file_count = request.GET.get('include_file_count', 'false')
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
        if not _native_tag_root_permission(request, repo_id):
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
            repo_tag_list = RepoTags.objects.get_all_by_repo_id(repo_id)
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
        if not _native_tag_root_permission(request, repo_id, write=True):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            repo_tag = RepoTags.objects.create_repo_tag(repo_id, tag_name, tag_color)
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
        
        # permission check
        if not _native_tag_root_permission(request, repo_id, write=True):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        tag_objs = list()
        try:
            for tag in tags:
                name = tag.get('name' ,'')
                color = tag.get('color', '')
                if name and color:
                    obj = RepoTags(repo_id=repo_id, name=name, color=color)
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
        if not _native_tag_root_permission(request, repo_id, write=True):
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
        if not _native_tag_root_permission(request, repo_id, write=True):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            RepoTags.objects.delete_repo_tag(repo_tag_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({"success": "true"}, status=status.HTTP_200_OK)
