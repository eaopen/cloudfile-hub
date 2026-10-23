"""Targeted tag/DRF/page regressions with explicit native RPC/ORM doubles."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.isolated_native import install

install()
suite = unittest.defaultTestLoader.loadTestsFromNames([
    'cloudfile_ext.v2.tests.test_tag_query_budget',
    'cloudfile_ext.v2.tests.test_tag_reads',
    'cloudfile_ext.v2.tests.test_tag_http',
    'cloudfile_ext.v2.tests.test_directory_page',
])
sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
