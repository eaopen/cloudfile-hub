"""v0.4 preview action and minimal trusted embedding contract."""
import base64
import sys
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from cloudfile_ext.file_actions import service
from cloudfile_ext.file_actions.embedding import configured_repo, library_entry

REPO = "12345678-1234-4234-8234-123456789abc"


def _configured(monkeypatch, base="https://preview.example.com/fileview"):
    monkeypatch.setattr(service, "settings", SimpleNamespace(
        SITE_ROOT="/", CF_PREVIEW_PROVIDER="eap-fileview",
        CF_PREVIEW_PUBLIC_URL=base,
        CF_FILE_ACTION_PREVIEW_EXTENSIONS=("pdf", "docx")))
    monkeypatch.setattr(service, "enabled_features", lambda: {
        "CF_ENABLE_FILE_PREVIEW": True,
    })


def test_default_requires_explicit_viewer_url_and_preserves_native(monkeypatch):
    _configured(monkeypatch, "")
    assert not service.external_preview_enabled()
    actions = service.get_actions(REPO, "/a/plan.pdf", username="reader@example.test")
    assert actions[0]["id"] == "native-preview"
    assert actions[0]["url"].endswith("/lib/" + REPO + "/file/a/plan.pdf")


def test_external_viewer_gets_actual_read_token_only_after_auth(monkeypatch):
    _configured(monkeypatch)
    calls = []

    class Seafile:
        def get_file_id_by_path(self, repo_id, path):
            calls.append(("file", repo_id, path))
            return "abcdef0123456789"

        def get_fileserver_access_token(self, repo_id, file_id, op, who, use_onetime):
            calls.append(("token", repo_id, file_id, op, who, use_onetime))
            return "short-lived-secret"

    seaserv = ModuleType("seaserv")
    seaserv.seafile_api = Seafile()
    utils = ModuleType("seahub.utils")
    utils.gen_file_get_url = lambda ticket, filename: (
        "https://files.example.com/files/" + ticket + "/" + filename)
    monkeypatch.setitem(sys.modules, "seaserv", seaserv)
    monkeypatch.setitem(sys.modules, "seahub.utils", utils)

    actions = service.get_actions(REPO, "/plans/test.pdf", username="reader@example.test")
    action = actions[0]
    assert action["id"] == "external-preview"
    assert action["writes"] is False and action["available"]
    assert action["url"].startswith("https://preview.example.com/fileview/onlinePreview?")
    source = base64.b64decode(parse_qs(urlsplit(action["url"]).query)["url"][0]).decode()
    assert source == "https://files.example.com/files/short-lived-secret/test.pdf"
    assert calls == [
        ("file", REPO, "/plans/test.pdf"),
        ("token", REPO, "abcdef0123456789", "download", "reader@example.test", False),
    ]


def test_missing_read_token_disables_action_instead_of_granting_fallback(monkeypatch):
    _configured(monkeypatch)
    seaserv = ModuleType("seaserv")
    seaserv.seafile_api = SimpleNamespace(get_file_id_by_path=lambda *_: None)
    monkeypatch.setitem(sys.modules, "seaserv", seaserv)
    actions = service.get_actions(REPO, "/a.pdf", username="reader")
    assert actions[0]["available"] is False
    assert "url" not in actions[0]
    assert actions[0]["reason"] == "preview_source_unavailable"


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "https://user:pass@preview.test",
    "https://preview.test/?token=secret", "//preview.test",
])
def test_untrusted_preview_base_is_never_enabled(monkeypatch, url):
    _configured(monkeypatch, url)
    assert not service.external_preview_enabled()


def test_embedding_accepts_only_trusted_repo_root():
    mapping = {"formal": {"repo_id": REPO, "root_path": "/"},
               "subdir": {"repo_id": REPO, "root_path": "/secret"},
               "bad": {"repo_id": "not-a-repo"}}
    assert configured_repo(mapping, "formal") == REPO
    assert configured_repo(mapping, "subdir") is None
    assert configured_repo(mapping, "bad") is None
    assert configured_repo(mapping, "../../formal") is None
    assert configured_repo(mapping, "missing") is None
    assert library_entry("/cfile/", REPO, "设计图纸") == (
        "/cfile/library/" + REPO + "/%E8%AE%BE%E8%AE%A1%E5%9B%BE%E7%BA%B8/")
