"""Require the editing schema before any editing state is used."""
from ..common.errors import ContractError


def require_storage(sql):
    sql.execute('SAVEPOINT cf_editing_transaction')
    sql.execute('RELEASE SAVEPOINT cf_editing_transaction')
    sql.execute("SELECT version FROM cf_schema_migration WHERE version='029_editing_core' AND state='applied' AND step=2")
    if sql.fetchone() is None:
        raise ContractError('EDIT_UNAVAILABLE', 'Editing schema required', 503)
