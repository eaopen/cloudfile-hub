"""Persisted auto-local registration mode tests without Django."""
import tempfile
from pathlib import Path
import unittest

from cloudfile_ext.storage.mode import auto_local_enabled


class StorageModeTests(unittest.TestCase):
    def test_explicit_env_is_enabled(self):
        self.assertTrue(auto_local_enabled({"CF_LIBRARY_STORAGE": "auto"}))

    def test_persisted_conf_is_enabled_without_env_switch(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / "seafile.conf").write_text(
                "[cloudfile_v2]\nauto_local_root = /shared/seafile/library-storage\n")
            self.assertTrue(auto_local_enabled({"SEAFILE_CENTRAL_CONF_DIR": str(root)}))
            (root / "seafile.conf").write_text(
                "[storage]\nenable_storage_classes = true\n")
            self.assertFalse(auto_local_enabled({"SEAFILE_CENTRAL_CONF_DIR": str(root)}))


if __name__ == "__main__":
    unittest.main()
