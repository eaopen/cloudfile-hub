"""Same-cursor CE qualification for control-plane management transactions.

Not an ACL solver. Owner/personal/group/public precedence follows native CE.
Caller already owns account, business binding and library authority locks.
"""
from ..common.errors import ContractError
from ..directory.project import qualified


class NativeLibraryQualification:
    def __init__(self, *, native_schema, native_table="Group", cloud_mode):
        if type(cloud_mode) is not bool:
            raise ValueError("explicit native cloud mode required")
        self.schema, self.table, self.cloud_mode = native_schema, native_table, cloud_mode
        self.members = qualified(native_schema, "GroupUser")
        self.groups = qualified(native_schema, native_table)
        self.structure = qualified(native_schema, "GroupStructure")

    @staticmethod
    def _permission(rows):
        if any(row[0] not in {"r", "rw"} for row in rows):
            raise ValueError("invalid native share")
        return "rw" if any(row[0] == "rw" for row in rows) else "r" if rows else None

    @staticmethod
    def _engines(cursor, native_schema=None, tables=()):
        for table in tables:
            if native_schema is None:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            else:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (native_schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ValueError("nontransactional qualification")

    def read(self, cursor, *, repo_id, username, owner):
        try:
            try:
                cursor.execute("SELECT @@transaction_isolation")
            except Exception as error:
                if not error.args or error.args[0] != 1193:
                    raise
                cursor.execute("SELECT @@tx_isolation")
            if cursor.fetchall() not in ((("REPEATABLE-READ",),), (("SERIALIZABLE",),)):
                raise ValueError("unsafe absence reads")
            if owner == username:
                return "rw"
            cursor.execute("SELECT permission,to_email FROM SharedRepo WHERE repo_id=%s AND to_email=%s LIMIT 2 FOR UPDATE", (repo_id, username))
            personal = cursor.fetchall()
            self._engines(cursor, tables=("SharedRepo",))
            if len(personal) > 1 or any(row[1] != username for row in personal):
                raise ValueError("ambiguous personal share")
            if personal:
                return self._permission(personal)
            cursor.execute("SELECT group_id,user_name FROM " + self.members + " WHERE user_name=%s ORDER BY group_id LIMIT 4097 FOR UPDATE", (username,))
            membership = cursor.fetchall()
            if (len(membership) > 4096 or any(type(row[0]) is not int or not 0 < row[0] <= 2147483647 or
                    row[1] != username for row in membership)):
                raise ValueError("invalid native memberships")
            ids = {row[0] for row in membership}
            if len(ids) != len(membership):
                raise ValueError("duplicate native memberships")
            def load_paths(selected):
                markers = ",".join(["%s"] * len(selected))
                cursor.execute("SELECT group_id,path FROM " + self.structure + " WHERE group_id IN (" + markers + ") ORDER BY group_id LIMIT 4097 FOR UPDATE", tuple(sorted(selected)))
                rows = cursor.fetchall()
                paths = {}
                for group, path in rows:
                    if group not in selected or group in paths or not isinstance(path, str) or len(path) > 1024:
                        raise ValueError("invalid native hierarchy")
                    tokens = path.split(", ")
                    if not 1 <= len(tokens) <= 128 or any(not t.isascii() or not t.isdecimal() or
                            t.startswith("0") or len(t) > 10 or int(t) > 2147483647 for t in tokens):
                        raise ValueError("invalid native path")
                    numbers = [int(t) for t in tokens]
                    if len(numbers) != len(set(numbers)) or numbers[-1] != group:
                        raise ValueError("invalid native hierarchy cycle")
                    paths[group] = numbers
                return paths
            if ids:
                direct = set(ids)
                first = load_paths(direct)
                ids.update(number for path in first.values() for number in path)
                if len(ids) > 4096:
                    raise ValueError("ancestor budget exceeded")
                markers = ",".join(["%s"] * len(ids))
                cursor.execute("SELECT group_id,parent_group_id FROM " + self.groups + " WHERE group_id IN (" + markers + ") ORDER BY group_id LIMIT 4097 FOR UPDATE", tuple(sorted(ids)))
                rows = cursor.fetchall()
                parents = {}
                for group, parent in rows:
                    if group not in ids or group in parents or type(parent) is not int or not -1 <= parent <= 2147483647:
                        raise ValueError("invalid native parent")
                    parents[group] = parent
                if set(parents) != ids:
                    raise ValueError("native group missing")
                paths = load_paths(ids)
                for group in direct:
                    chain, current = [], group
                    while current > 0:
                        if current in chain or len(chain) >= 128 or current not in parents:
                            raise ValueError("native hierarchy cycle")
                        chain.append(current)
                        current = parents[current]
                    if len(chain) > 1 or current == -1:
                        if current != -1:
                            raise ValueError("native department root missing")
                        expected = list(reversed(chain))
                        if any(paths.get(node) != expected[:index + 1] for index, node in enumerate(expected)):
                            raise ValueError("native hierarchy mismatch")
                cursor.execute("SELECT permission FROM RepoGroup WHERE repo_id=%s AND group_id IN (" + markers + ") ORDER BY group_id LIMIT 4097 FOR UPDATE", (repo_id, *sorted(ids)))
                shared = cursor.fetchall()
                if len(shared) > 4096:
                    raise ValueError("share budget exceeded")
                self._engines(cursor, tables=("RepoGroup",))
                permission = self._permission(shared)
            else:
                permission = None
            self._engines(cursor, native_schema=self.schema, tables=("GroupUser", "GroupStructure", self.table))
            if permission:
                return permission
            if self.cloud_mode:
                return None
            cursor.execute("SELECT permission FROM InnerPubRepo WHERE repo_id=%s LIMIT 2 FOR UPDATE", (repo_id,))
            public = cursor.fetchall()
            self._engines(cursor, tables=("InnerPubRepo",))
            if len(public) > 1:
                raise ValueError("ambiguous public share")
            return self._permission(public)
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Native library qualification is unavailable", 503) from None
