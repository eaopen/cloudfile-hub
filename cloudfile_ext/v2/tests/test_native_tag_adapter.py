"""Native CE user tags use one sparse RepoTags/FileTags binding store."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.tag_native import user_tag_names
from seahub.api2.endpoints.file_tag import RepoFileTagsView, RepoFileTagView, FileTagsView


RID = '00000000-0000-4000-8000-000000000001'
OTHER = '00000000-0000-4000-8000-000000000002'


def request(view, method, path, data=None, **route):
    factory = APIRequestFactory()
    raw = (factory.get(path, data or {}) if method == 'GET' else
           factory.post(path, data or {}, format='json') if method == 'POST' else
           factory.delete(path, data or {}, format='json'))
    force_authenticate(raw, SimpleNamespace(username='current', is_authenticated=True, is_active=True))
    return view.as_view()(raw, **route)


class NativeTagWriteTests(TestCase):
    def test_user_names_allow_unicode_but_reserve_system_prefix(self):
        self.assertEqual(user_tag_names('设计, review,设计'), ['设计', 'review'])
        with self.assertRaises(PermissionError):
            user_tag_names('SYS_PROJECT_1')
        with self.assertRaises(ValueError):
            user_tag_names('A,')

    def test_cross_repo_tag_id_never_binds(self):
        with patch('seahub.api2.endpoints.file_tag._tag_target_request',
                   return_value=('/docs/a.txt', False)), \
             patch('seahub.api2.endpoints.file_tag.RepoTags.objects.get_repo_tag_by_id',
                   return_value=SimpleNamespace(repo_id=OTHER, name='design')), \
             patch('seahub.api2.endpoints.file_tag.FileTags.objects.add_file_tag') as bind:
            response = request(RepoFileTagsView, 'POST', '/api/v2.1/repos/'+RID+'/file-tags/',
                               {'file_path': '/docs/a.txt', 'repo_tag_id': 123}, repo_id=RID)
        self.assertEqual(response.status_code, 404)
        bind.assert_not_called()

    def test_direct_binding_delete_checks_original_repo(self):
        binding = SimpleNamespace(file_uuid=SimpleNamespace(repo_id=OTHER),
                                  repo_tag=SimpleNamespace(repo_id=RID, name='USER'),
                                  pk=42)
        with patch('seahub.api2.endpoints.file_tag.FileTags.objects.get_file_tag_by_id',
                   return_value=binding), \
             patch('seahub.api2.endpoints.file_tag.FileTags.objects.delete_file_tag') as remove:
            response = request(RepoFileTagView, 'DELETE', '/api/v2.1/repos/'+RID+'/file-tags/42/',
                               repo_id=RID, file_tag_id=42)
        self.assertEqual(response.status_code, 404)
        remove.assert_not_called()

    def test_deprecated_user_add_now_writes_ce_filetags_not_legacy(self):
        with patch('seahub.api2.endpoints.file_tag.seafile_api.get_repo',
                   return_value=SimpleNamespace(is_virtual=False)), \
             patch('seahub.api2.endpoints.file_tag.seafile_api.get_file_id_by_path',
                   return_value='native-id'), \
             patch('seahub.api2.endpoints.file_tag.authorize_tag_target'), \
             patch('seahub.api2.endpoints.file_tag.write_resource_tags',
                   return_value=[{'id': 2, 'name': '设计', 'source': 'repo'}]) as write, \
             patch('seahub.api2.endpoints.file_tag.FileTag.objects.get_or_create_file_tag') as legacy:
            response = request(FileTagsView, 'POST', '/api/v2.1/repos/'+RID+'/tags/',
                               {'path': '/docs/a.txt', 'is_dir': 'false', 'names': '设计'}, repo_id=RID)
        self.assertEqual(response.status_code, 200)
        write.assert_called_once_with(RID, '/docs/a.txt', False, ['设计'])
        legacy.assert_not_called()
