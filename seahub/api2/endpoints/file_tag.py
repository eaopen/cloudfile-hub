import os
import posixpath
import re
import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.translation import gettext_lazy as _

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error, to_python_boolean
from seahub.tags.models import FileTag
from seahub.file_tags.models import FileTags
from seahub.repo_tags.models import RepoTags
from seahub.utils import normalize_file_path
from seahub.constants import PERMISSION_READ_WRITE
from seahub.views import check_folder_permission

from seaserv import seafile_api
from cloudfile_ext.v2.tag_native import (authorize_tag_target, authorize_tag_label, require_repo_tag,
                                         user_tag_names, read_resource_tags, write_resource_tags,
                                         delete_resource_user_tag)

logger = logging.getLogger(__name__)


def _tag_error(error):
    if isinstance(error, ValueError):
        return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid tag request.')
    if isinstance(error, PermissionError):
        return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
    if isinstance(error, FileNotFoundError):
        return api_error(status.HTTP_404_NOT_FOUND, 'Tag resource not found.')
    logger.exception('Native CE tag request unavailable', exc_info=error)
    return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Tag service unavailable.')


def _tag_target_request(request, repo_id, *, write):
    params = request.data if request.method == 'POST' else request.GET
    path = params.get('file_path')
    if not isinstance(path, str) or not path:
        raise ValueError('missing file_path')
    is_dir = to_python_boolean(params.get('is_dir', 'false'))
    authorize_tag_target(request.user, repo_id, path, is_dir=is_dir, write=write)
    return path, is_dir


class RepoFileTagsView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        try:
            file_path, is_dir = _tag_target_request(request, repo_id, write=False)
            file_tags = FileTags.objects.get_file_tag_by_path(repo_id, file_path, is_dir=is_dir)
            return Response({'file_tags': file_tags}, status=status.HTTP_200_OK)
        except Exception as error:
            return _tag_error(error)

    def post(self, request, repo_id):
        try:
            file_path, is_dir = _tag_target_request(request, repo_id, write=True)
            repo_tag_id = request.data.get('repo_tag_id')
            if not repo_tag_id:
                raise ValueError('missing repo_tag_id')
            repo_tag = require_repo_tag(repo_id, RepoTags.objects.get_repo_tag_by_id(repo_tag_id))
            authorize_tag_label(request.user, repo_id, repo_tag.name)
            existing = FileTags.objects.get_file_tag(repo_id, repo_tag_id, file_path, is_dir=is_dir)
            if existing:
                return api_error(status.HTTP_400_BAD_REQUEST, 'File tag already exists.')
            file_tag = FileTags.objects.add_file_tag(repo_id, repo_tag_id, file_path, is_dir=is_dir)
            return Response({'file_tag': file_tag.to_dict()}, status=status.HTTP_201_CREATED)
        except Exception as error:
            return _tag_error(error)


class RepoFileTagView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def delete(self, request, repo_id, file_tag_id):
        try:
            binding = FileTags.objects.get_file_tag_by_id(file_tag_id)
            if binding is None:
                raise FileNotFoundError('missing binding')
            repo_tag = require_repo_tag(repo_id, binding.repo_tag)
            target = binding.file_uuid
            if target.repo_id != repo_id:
                raise FileNotFoundError('cross-repository tag binding')
            path = posixpath.join(target.parent_path, target.filename)
            authorize_tag_target(request.user, repo_id, path, is_dir=target.is_dir, write=True)
            authorize_tag_label(request.user, repo_id, repo_tag.name)
            FileTags.objects.delete_file_tag(file_tag_id)
            return Response({'success': 'true'}, status=status.HTTP_200_OK)
        except Exception as error:
            return _tag_error(error)


# Deprecated
def check_parameter(func):
    """check if the param is given, check if the file or dir exists, and split file_path to
    parent_path and filename
    """
    def _decorated(view, request, *args, **kwargs):
        file_path = None
        is_dir = None
        repo_id = kwargs.get('repo_id')
        if request.method == 'GET':
            file_path = request.GET.get('path', '')
            is_dir = request.GET.get('is_dir', '')
        elif request.method in ['POST', 'PUT']:
            file_path = request.data.get('path', '')
            is_dir = request.data.get('is_dir', '')
        elif request.method == 'DELETE':
            file_path = request.GET.get('path', '')
            is_dir = request.GET.get('is_dir', '')

        try:
            repo = seafile_api.get_repo(repo_id)
        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not file_path:
            error_msg = "p %s invalid." % file_path
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            is_dir = to_python_boolean(is_dir)
        except ValueError:
            error_msg = 'is_dir invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # split file_path to filename and parent_path
        # and check if the file exists
        new_file_path = file_path.rstrip('/')
        parent_path = os.path.dirname(new_file_path)
        filename = os.path.basename(new_file_path)
        if is_dir:
            dir_id = seafile_api.get_dir_id_by_path(repo_id, new_file_path)
            if not dir_id:
                error_msg = 'Folder %s not found.' % file_path
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)


        else:
            if filename.strip() == '':
                error_msg = 'p %s invalid' % file_path
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            file_id = seafile_api.get_file_id_by_path(repo_id, new_file_path)
            if not file_id:
                error_msg = 'File %s not found.' % file_path
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)



        try:
            authorize_tag_target(request.user, repo_id, new_file_path,
                                 is_dir=is_dir, write=request.method != 'GET')
        except Exception as error:
            return _tag_error(error)

        kwargs['parent_path'] = parent_path
        kwargs['filename'] = filename
        kwargs['is_dir'] = is_dir
        return func(view, request, *args, **kwargs)
    return _decorated

def check_tagname(tagname):
    return True if re.match(r'^[\.\w-]+$', tagname, re.U) else False

class FileTagsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @check_parameter
    def get(self, request, repo_id, parent_path, filename, is_dir):
        path = posixpath.join(parent_path, filename)
        try:
            return Response({'tags': read_resource_tags(repo_id, path, is_dir)},
                            status=status.HTTP_200_OK)
        except Exception as error:
            return _tag_error(error)

    @check_parameter
    def put(self, request, repo_id, parent_path, filename, is_dir):
        names = request.data.get('names', None)
        if names is None:
            error_msg = "Tag can not be empty"
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        res_tag_list = []
        if not names.strip():
            name_list = []
        else:
            name_list = [name.strip() for name in names.split(",")]
            for name in name_list:
                if not check_tagname(name):
                    error_msg = _('Tag can only contain letters, numbers, dot, hyphen or underscore.')
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        FileTag.objects.delete_all_filetag_by_path(repo_id, parent_path,
                                                  filename, is_dir)
        for name in name_list:
            tag_obj, created = FileTag.objects.get_or_create_file_tag(
                    repo_id, parent_path, filename, is_dir, name,
                    request.user.username
            )
            res_tag_list.append(tag_obj.to_dict())

        return Response({"tags": res_tag_list}, status=status.HTTP_200_OK)

    @check_parameter
    def post(self, request, repo_id, parent_path, filename, is_dir):
        names = request.POST.get('names', None)
        if names is None or not names.strip():
            error_msg = "Tag can not be empty"
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        name_list = [name.strip() for name in names.split(",")]
        for name in name_list:
            if not check_tagname(name):
                error_msg = _('Tag can only contain letters, numbers, dot, hyphen or underscore.')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        res_tag_list = []
        for name in name_list:
            tag_obj, created = FileTag.objects.get_or_create_file_tag(
                    repo_id, parent_path, filename, is_dir, name,
                    request.user.username
            )
            res_tag_list.append(tag_obj.to_dict())
        return Response({"tags": res_tag_list}, status=status.HTTP_200_OK)

class FileTagView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @check_parameter
    def delete(self, request, repo_id, parent_path, filename, name, is_dir):
        if not name or not check_tagname(name):
            error_msg = _('Tag can only contain letters, numbers, dot, hyphen or underscore.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        if FileTag.objects.delete_file_tag_by_path(repo_id,
                parent_path, filename, is_dir, name):
            return Response({"success": True}, status=status.HTTP_200_OK)
        else:
            return Response({"success": True}, status=status.HTTP_202_ACCEPTED)
