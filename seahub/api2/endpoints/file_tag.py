import os
import re
import posixpath
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
from cloudfile_ext.v2.acl_runtime import ACLUnavailable
from cloudfile_ext.v2.tag_native import (
    authorize_tag_target, authorize_tag_label, require_repo_tag, user_tag_names,
    read_resource_tags, write_resource_tags, delete_resource_user_tag,
)

from seaserv import seafile_api

logger = logging.getLogger(__name__)


def _tag_error(error):
    if isinstance(error, PermissionError):
        return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
    if isinstance(error, FileNotFoundError):
        return api_error(status.HTTP_404_NOT_FOUND, 'Tag or target not found.')
    if isinstance(error, ValueError):
        return api_error(status.HTTP_400_BAD_REQUEST, str(error))
    return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Permission service unavailable.')


def _tag_target_request(request, repo_id, write=False):
    values = request.data if write else request.GET
    path = values.get('file_path')
    return authorize_tag_target(request.user, repo_id, path, False, write), False


class RepoFileTagsView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        """list all tags of a file.
        """
        try:
            file_path, _ = _tag_target_request(request, repo_id)
        except (PermissionError, FileNotFoundError, ValueError, ACLUnavailable) as error:
            return _tag_error(error)

        try:
            file_tags = FileTags.objects.get_file_tag_by_path(repo_id, file_path)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({"file_tags": file_tags}, status=status.HTTP_200_OK)

    def post(self, request, repo_id):
        """add a tag for a file.
        """
        repo_tag_id = request.data.get('repo_tag_id')
        if not repo_tag_id:
            return api_error(status.HTTP_400_BAD_REQUEST, 'repo_tag_id invalid.')
        try:
            file_path, _ = _tag_target_request(request, repo_id, True)
            repo_tag = require_repo_tag(repo_id, RepoTags.objects.get_repo_tag_by_id(repo_tag_id))
            authorize_tag_label(request.user, repo_id, repo_tag.name)
        except (PermissionError, FileNotFoundError, ValueError, ACLUnavailable) as error:
            return _tag_error(error)

        file_tag = FileTags.objects.get_file_tag(repo_id, repo_tag_id, file_path)
        if file_tag:
            error_msg = 'file tag %s already exist.' % repo_tag_id
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            file_tag = FileTags.objects.add_file_tag(repo_id, repo_tag_id, file_path)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        from cloudfile_ext.audit.events import record_resource_tag_event
        record_resource_tag_event(
            operator=request.user.username, repo_id=repo_id, path=file_path,
            kind='file', operation='tag_add', tag_name=repo_tag.name)
        return Response({"file_tag": file_tag.to_dict()}, status=status.HTTP_201_CREATED)


class RepoFileTagView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def delete(self, request, repo_id, file_tag_id):
        """delete a tag from a file
        """
        file_tag = FileTags.objects.get_file_tag_by_id(file_tag_id)
        if not file_tag:
            error_msg = 'file_tag %s not found.' % file_tag_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if file_tag.repo_tag.repo_id != repo_id or file_tag.file_uuid.repo_id != repo_id:
            return api_error(status.HTTP_404_NOT_FOUND, 'file_tag not found.')
        path = posixpath.join(file_tag.file_uuid.parent_path, file_tag.file_uuid.filename)
        removed_tag = file_tag.repo_tag.name

        try:
            authorize_tag_target(request.user, repo_id, path, file_tag.file_uuid.is_dir, True)
            authorize_tag_label(request.user, repo_id, removed_tag)
        except (PermissionError, FileNotFoundError, ValueError, ACLUnavailable) as error:
            return _tag_error(error)
        try:
            FileTags.objects.delete_file_tag(file_tag_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        from cloudfile_ext.audit.events import record_resource_tag_event
        record_resource_tag_event(
            operator=request.user.username, repo_id=repo_id, path=path,
            kind='file', operation='tag_remove', tag_name=removed_tag)
        return Response({"success": "true"}, status=status.HTTP_200_OK)


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
            authorize_tag_target(request.user, repo_id, new_file_path, is_dir, request.method != 'GET')
        except (PermissionError, FileNotFoundError, ValueError, ACLUnavailable) as error:
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
        tags = read_resource_tags(repo_id, posixpath.join(parent_path, filename), is_dir)
        return Response({"tags": tags}, status=status.HTTP_200_OK)

    @check_parameter
    def put(self, request, repo_id, parent_path, filename, is_dir):
        try:
            names = user_tag_names(request.data.get('names'))
        except (PermissionError, ValueError) as error:
            return _tag_error(error)
        tags = write_resource_tags(repo_id, posixpath.join(parent_path, filename), is_dir,
                                   names, replace=True)
        return Response({"tags": tags}, status=status.HTTP_200_OK)

    @check_parameter
    def post(self, request, repo_id, parent_path, filename, is_dir):
        try:
            names = user_tag_names(request.data.get('names'))
            if not names:
                raise ValueError('Tag can not be empty')
        except (PermissionError, ValueError) as error:
            return _tag_error(error)
        tags = write_resource_tags(repo_id, posixpath.join(parent_path, filename), is_dir, names)
        return Response({"tags": tags}, status=status.HTTP_200_OK)


class FileTagView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @check_parameter
    def delete(self, request, repo_id, parent_path, filename, name, is_dir):
        try:
            user_tag_names(name)
        except (PermissionError, ValueError) as error:
            return _tag_error(error)
        path = posixpath.join(parent_path, filename)
        tags = read_resource_tags(repo_id, path, is_dir)
        if any(tag['name'] == name and tag['source'] == 'legacy' for tag in tags):
            return api_error(status.HTTP_409_CONFLICT, 'Legacy tag is read-only.')
        deleted = delete_resource_user_tag(repo_id, path, is_dir, name)
        return Response({"success": True}, status=status.HTTP_200_OK if deleted else status.HTTP_202_ACCEPTED)
