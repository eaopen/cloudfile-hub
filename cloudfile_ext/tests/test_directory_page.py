"""Native paginated requests dispatch to the current V2 authority adapter."""
import ast
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]

class PageDispatchTest(unittest.TestCase):
    def test_public_paged_requests_delegate_to_v2(self):
        tree = ast.parse((ROOT / 'seahub/api2/endpoints/dir.py').read_text())
        view = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'DirView')
        method = next(n for n in view.body if isinstance(n, ast.FunctionDef) and n.name == 'get')
        method.decorator_list = []
        view.body, view.bases, view.decorator_list = [method], [], []
        scope = {}
        exec(compile(ast.Module(body=[view], type_ignores=[]), str(ROOT), 'exec'), scope)
        for query in ({'start': '0'}, {'limit': '50'}):
            request = SimpleNamespace(GET=query)
            delegate = Mock(return_value=object())
            with patch.dict(sys.modules, {'cloudfile_ext.v2.directory_page': SimpleNamespace(directory_page=delegate)}):
                result = scope['DirView']().get(request, 'repo')
            delegate.assert_called_once_with(request, 'repo')
            self.assertIs(result, delegate.return_value)
