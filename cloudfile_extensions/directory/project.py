"""Same-connection native membership reconciliation; not a readiness grant.

Generation assertion and audit are mandatory trusted adapters. No HTTP/default
worker registration, deferred RPC mutation or per-user SQL snapshot is added.
"""
from ..common.errors import ContractError
from ..common.validation import identifier
from ..jobs.authority import scope_locks
from .group_maps import GroupMaps
from .memberships import plan_memberships
from .protocol import validate_subject


def qualified(schema, table):
    identifier(schema, maximum=64)
    identifier(table, maximum=64)
    return "`" + schema.replace("`", "``") + "`.`" + table.replace("`", "``") + "`"


class NativeMembershipProjector:
    def __init__(self, connection, *, native_schema, identity_schema, provider,
                 assert_generation, audit_hook, attribute_allowlist=(), native_table="Group"):
        if not connection.get_autocommit() or not callable(assert_generation) or not callable(audit_hook):
            raise ValueError("dedicated connection, generation assertion and transactional audit are required")
        identifier(provider, maximum=32)
        self.connection, self.provider = connection, provider
        self.native_schema, self.identity_schema, self.native_table = native_schema, identity_schema, native_table
        self.groups = qualified(native_schema, native_table)
        self.members = qualified(native_schema, "GroupUser")
        self.accounts = qualified(native_schema, "EmailUser")
        self.profiles = qualified(identity_schema, "profile_profile")
        self.assert_generation, self.audit = assert_generation, audit_hook
        self.allowlist = frozenset(attribute_allowlist)

    def _members(self, cursor, username):
        cursor.execute("SELECT group_id,user_name,is_staff FROM " + self.members + " WHERE user_name=%s ORDER BY group_id LIMIT 16385 FOR UPDATE", (username,))
        rows = cursor.fetchall()
        if (len(rows) > 16384 or any(row[1] != username or type(row[2]) is not int or row[2] not in (0, 1) for row in rows)):
            raise ValueError()
        return rows

    def _hierarchy(self, cursor, owned, groups):
        departments = {group for group, item in owned.items() if item["subject_type"] == "dept"}
        if not departments:
            return {}
        table = qualified(self.native_schema, "GroupStructure")
        markers = ",".join(["%s"] * len(departments))
        cursor.execute("SELECT group_id,path FROM " + table + " WHERE group_id IN (" + markers + ") ORDER BY group_id FOR UPDATE", tuple(sorted(departments)))
        rows = cursor.fetchall()
        if len(rows) != len(departments):
            raise ValueError()
        paths = {}
        for group, path in rows:
            if not isinstance(path, str) or len(path) > 1024:
                raise ValueError()
            tokens = path.split(", ")
            if not 1 <= len(tokens) <= 128 or any(not token.isascii() or not token.isdecimal() or token.startswith("0") for token in tokens):
                raise ValueError()
            ids = [int(token) for token in tokens]
            if ids[-1] != group or len(set(ids)) != len(ids) or any(value not in departments for value in ids):
                raise ValueError()
            if any(owned[value]["namespace"] != owned[group]["namespace"] or
                   groups[value] != (-1 if index == 0 else ids[index-1]) for index, value in enumerate(ids)):
                raise ValueError()
            paths[group] = set(ids)
        return paths

    def apply(self, subject, epoch, *, native_username):
        identifier(native_username)
        if not isinstance(epoch, str) or len(epoch) != 32 or any(char not in "0123456789abcdef" for char in epoch):
            raise ContractError("INVALID_REQUEST", "Invalid subject generation", 400)
        subject = validate_subject(subject, requested_user_id=subject.get("userId") if isinstance(subject, dict) else None,
                                   attribute_allowlist=self.allowlist)
        user_id = subject["userId"]
        scopes = [{"type": "provider", "provider": self.provider, "external_id": self.provider},
                  {"type": "user", "provider": self.provider, "external_id": user_id}]
        try:
            with scope_locks(self.connection, scopes):
                self.connection.begin()
                try:
                    self.assert_generation(user_id, epoch)
                    with self.connection.cursor() as cursor:
                        cursor.execute("SELECT email,is_active FROM " + self.accounts + " WHERE email=%s FOR UPDATE", (native_username,))
                        account = cursor.fetchall()
                        if (len(account) != 1 or account[0][0] != native_username or
                                type(account[0][1]) is not int or account[0][1] not in (0, 1) or
                                (subject["status"] == "active" and account[0][1] != 1)):
                            raise ValueError()
                        cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (native_username, user_id))
                        if cursor.fetchall() != ((native_username, user_id),):
                            raise ValueError()
                        mappings = GroupMaps(self.connection).read(self.provider)
                        owned = {item["group_id"]: item for item in mappings}
                        if owned:
                            markers = ",".join(["%s"] * len(owned))
                            cursor.execute("SELECT group_id,parent_group_id FROM " + self.groups + " WHERE group_id IN (" + markers + ") ORDER BY group_id FOR UPDATE", tuple(sorted(owned)))
                            groups = dict(cursor.fetchall())
                            if set(groups) != set(owned) or any(
                                    (item["subject_type"] == "group" and groups[group] != 0) or
                                    (item["subject_type"] == "dept" and groups[group] != -1 and groups[group] not in owned)
                                    for group, item in owned.items()):
                                raise ValueError()
                        else:
                            cursor.execute("SELECT group_id FROM " + self.groups + " WHERE group_id=0 FOR UPDATE")
                            groups = {}
                        hierarchy = self._hierarchy(cursor, owned, groups)
                        current = self._members(cursor, native_username)
                        if any(group in owned and staff != 0 for group, _, staff in current):
                            # Never silently remove/rewrite staff delegation.
                            raise ValueError()
                        required = [(self.native_schema, self.native_table), (self.native_schema, "EmailUser"),
                                    (self.native_schema, "GroupUser"), (self.identity_schema, "profile_profile")]
                        cursor.execute("SELECT DATABASE()")
                        required.append((cursor.fetchone()[0], "cf_sso_group_map"))
                        if hierarchy:
                            required.append((self.native_schema, "GroupStructure"))
                        for schema, table in required:
                            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
                            if cursor.fetchall() != (("InnoDB",),):
                                raise ValueError()
                        plan = plan_memberships(subject, user_id=user_id, provider_id=self.provider,
                                                mappings=mappings, current_groups=[row[0] for row in current],
                                                attribute_allowlist=self.allowlist)
                        desired = set(plan.add) | set(plan.retain)
                        if any(not hierarchy[group].issubset(desired) for group in desired if group in hierarchy):
                            # Native implicit ancestors may not introduce a
                            # department absent from this coherent source snapshot.
                            raise ValueError()
                        for group in plan.remove:
                            cursor.execute("DELETE FROM " + self.members + " WHERE group_id=%s AND user_name=%s AND is_staff=0", (group, native_username))
                            if cursor.rowcount != 1:
                                raise ValueError()
                        for group in plan.add:
                            cursor.execute("INSERT INTO " + self.members + "(group_id,user_name,is_staff) VALUES(%s,%s,0)", (group, native_username))
                        actual = self._members(cursor, native_username)
                        expected = (set(row[0] for row in current) - set(plan.remove)) | set(plan.add)
                        if set(row[0] for row in actual) != expected or len(actual) != len(expected):
                            raise ValueError()
                        if plan.add or plan.remove:
                            self.audit(cursor, dict(actor=user_id, action="subject.memberships", provider=self.provider,
                                                    epoch=epoch, added=plan.add, removed=plan.remove))
                        # Repeat after row-lock waits and all effects, before SQL
                        # commit. Callback must reject lost/expired generation.
                        self.assert_generation(user_id, epoch)
                    self.connection.commit()
                    return plan
                finally:
                    self.connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError("PROJECTION_UNAVAILABLE", "Native memberships are unavailable", 503) from None
