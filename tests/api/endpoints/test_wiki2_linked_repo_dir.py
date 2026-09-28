from types import SimpleNamespace

from django.test import SimpleTestCase
from mock import DEFAULT, patch

from seahub.api2.endpoints.wiki2 import Wiki2LinkedRepoDirView


class Wiki2LinkedRepoDirViewTest(SimpleTestCase):
    def test_list_linked_repo_directory_with_paged_listing_result(self):
        wiki_id = '11111111-1111-1111-1111-111111111111'
        linked_repo_id = '22222222-2222-2222-2222-222222222222'
        request = SimpleNamespace(
            user=SimpleNamespace(username='alice@example.com'), GET={'p': '/'})
        directories = [{'name': 'documents', 'type': 'dir'}]
        files = [{'name': 'readme.txt', 'type': 'file'}]

        with patch.multiple(
                'seahub.api2.endpoints.wiki2',
                Wiki=DEFAULT, Wiki2Settings=DEFAULT, seafile_api=DEFAULT,
                get_repo_owner=DEFAULT, check_wiki_permission=DEFAULT,
                check_folder_permission=DEFAULT, get_dir_file_info_list=DEFAULT,
        ) as mocks:
            mocks['Wiki'].objects.get.return_value = SimpleNamespace(owner=None)
            mocks['Wiki2Settings'].objects.filter.return_value.first.return_value = (
                SimpleNamespace(enable_link_repos=True,
                                get_linked_repos=lambda: [linked_repo_id]))
            mocks['seafile_api'].get_repo.return_value = repo = object()
            mocks['seafile_api'].get_dir_id_by_path.return_value = 'dir-id'
            mocks['get_repo_owner'].return_value = request.user.username
            mocks['check_wiki_permission'].return_value = 'r'
            mocks['check_folder_permission'].return_value = 'r'
            mocks['get_dir_file_info_list'].return_value = (directories, files, False)

            response = Wiki2LinkedRepoDirView().get(request, wiki_id, linked_repo_id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['dirent_list'], directories + files)
        mocks['get_dir_file_info_list'].assert_called_once_with(
            request.user.username, '', repo, '/', False, 0)
