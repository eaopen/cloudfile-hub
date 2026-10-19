"""Virtual libraries must not acquire an independent sharing authority."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


def test_virtual_library_share_rejects_before_owner_lookup_or_mutation():
    # Execute the real public mutation entry point with a valid rw request;
    # unsupported admin input must not be the reason this denial passes.
    source = Path(__file__).resolve().parents[2] / 'seahub/api2/views.py'
    tree = ast.parse(source.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == 'SharedRepo')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                  and node.name == 'put')
    owner = Mock(side_effect=AssertionError('virtual library reached owner lookup'))
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(is_virtual=True)
    env = dict(status=SimpleNamespace(HTTP_400_BAD_REQUEST=400, HTTP_404_NOT_FOUND=404),
        get_available_repo_perms=lambda: ('r', 'rw'), seafile_api=api, get_repo_owner=owner,
        api_error=lambda code, message: SimpleNamespace(status_code=code))
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'), env)
    request = SimpleNamespace(GET={'share_type': 'personal', 'permission': 'rw', 'user': 'other'},
                              user=SimpleNamespace(username='owner'))
    assert env['put'](object(), request, 'repo').status_code == 400
    owner.assert_not_called()
    api.share_repo.assert_not_called()
