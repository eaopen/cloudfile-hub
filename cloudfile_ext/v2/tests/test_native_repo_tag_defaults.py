"""Native CE RepoTags keeps optional counts but does not scan bindings by default."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate

from seahub.api2.endpoints.repo_tags import RepoTagsView


RID = "00000000-0000-4000-8000-000000000001"


class RepoTagCountDefaultTests(TestCase):
    def request(self, params=None):
        request = APIRequestFactory().get(
            "/api/v2.1/repos/%s/repo-tags/" % RID, params or {}
        )
        force_authenticate(
            request, SimpleNamespace(username="current", is_authenticated=True, is_active=True)
        )
        definition = Mock()
        definition.pk = 3
        definition.to_dict.return_value = {
            "repo_tag_id": 3, "repo_id": RID, "tag_name": "design", "tag_color": "#aaa"
        }
        with patch("seahub.api2.endpoints.repo_tags.seafile_api.get_repo", return_value=object()), \
             patch("seahub.api2.endpoints.repo_tags.check_folder_permission", return_value="r"), \
             patch("seahub.api2.endpoints.repo_tags.RepoTags.objects.get_all_by_repo_id",
                   return_value=[definition]), \
             patch("seahub.api2.endpoints.repo_tags.FileTags.objects.select_related") as file_tags:
            file_tags.return_value.filter.return_value = [SimpleNamespace(repo_tag_id=3)]
            response = RepoTagsView.as_view()(request, repo_id=RID)
        return response, file_tags

    def test_count_is_not_read_by_default(self):
        response, file_tags = self.request()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["repo_tags"]), 1)
        file_tags.assert_not_called()

    def test_count_is_still_supported_when_explicitly_requested(self):
        response, file_tags = self.request({"include_file_count": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["repo_tags"][0]["files_count"], 1)
        file_tags.assert_called_once()

    def test_invalid_count_parameter_still_returns_400(self):
        response, file_tags = self.request({"include_file_count": "unknown"})
        self.assertEqual(response.status_code, 400)
        file_tags.assert_not_called()
