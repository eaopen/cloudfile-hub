"""Read exact persisted ownership; no provisioning or implicit legacy adoption."""

from ..common.errors import ContractError
from ..common.validation import identifier


class GroupMaps:
    def __init__(self, connection):
        if not connection.get_autocommit():
            raise ValueError("group map reader requires a dedicated autocommit connection")
        self.connection = connection

    def read(self, provider_id):
        identifier(provider_id, maximum=32)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT provider,subject_type,namespace,external_id,group_id "
                               "FROM cf_sso_group_map WHERE provider=%s ORDER BY id LIMIT 16385", (provider_id,))
                rows = cursor.fetchall()
            if len(rows) > 16384:
                raise ValueError()
            result, keys, native = [], set(), set()
            for provider, kind, namespace, external_id, group_id in rows:
                if provider != provider_id or kind not in {"dept", "group"}:
                    raise ValueError()
                identifier(namespace)
                identifier(external_id)
                key = (kind, namespace, external_id)
                if (key in keys or group_id in native or type(group_id) is not int or
                        not 1 <= group_id <= 2147483647):
                    raise ValueError()
                keys.add(key)
                native.add(group_id)
                result.append(dict(provider=provider, subject_type=kind, namespace=namespace,
                                   external_id=external_id, group_id=group_id))
            return result
        except Exception:
            raise ContractError("PROJECTION_UNAVAILABLE", "Native group ownership is unavailable", 503) from None
