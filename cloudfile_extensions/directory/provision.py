"""Atomic native role/department creation and mapping on one MySQL connection.

Trusted internal adapter only; no HTTP registration or readiness grant. Native
schema/table are deployment configuration, not request fields. Membership
publication still requires its own complete native coordination.
"""
import time

from ..common.errors import ContractError
from ..common.validation import identifier
from ..jobs.authority import scope_locks


class NativeGroupProvisioner:
    def __init__(self, connection, *, native_schema, management_guard, audit_hook,
                 native_table="Group"):
        if not connection.get_autocommit() or not callable(management_guard) or not callable(audit_hook):
            raise ValueError("dedicated connection, management guard and transactional audit are required")
        identifier(native_schema, maximum=64)
        identifier(native_table, maximum=64)
        self.connection = connection
        self.native_schema, self.native_table = native_schema, native_table
        self.table = "`" + native_schema.replace("`", "``") + "`.`" + native_table.replace("`", "``") + "`"
        self.structure = "`" + native_schema.replace("`", "``") + "`.`GroupStructure`"
        self.guard, self.audit = management_guard, audit_hook

    def ensure(self, *, actor, provider, namespace, external_id, name):
        return self._ensure(actor=actor, provider=provider, namespace=namespace,
                            external_id=external_id, name=name, kind="group", parent=None)

    def ensure_department(self, *, actor, provider, namespace, external_id, name, parent=None):
        if parent is not None:
            identifier(parent)
            if parent == external_id:
                raise ContractError("INVALID_REQUEST", "Department cannot parent itself", 400)
        return self._ensure(actor=actor, provider=provider, namespace=namespace,
                            external_id=external_id, name=name, kind="dept", parent=parent)

    def _parent(self, cursor, provider, namespace, parent):
        cursor.execute("SELECT provider,subject_type,namespace,external_id,group_id FROM cf_sso_group_map WHERE provider=%s AND subject_type='dept' AND namespace=%s AND external_id=%s FOR UPDATE",
                       (provider, namespace, parent))
        mapped = cursor.fetchall()
        if len(mapped) != 1 or mapped[0][:4] != (provider, "dept", namespace, parent):
            raise ValueError()
        parent_id = mapped[0][4]
        cursor.execute("SELECT path FROM " + self.structure + " WHERE group_id=%s FOR UPDATE", (parent_id,))
        paths = cursor.fetchall()
        if len(paths) != 1 or not isinstance(paths[0][0], str):
            raise ValueError()
        tokens = paths[0][0].split(", ")
        if not 1 <= len(tokens) < 128 or any(not token.isascii() or not token.isdecimal() or token.startswith("0") for token in tokens):
            raise ValueError()
        ids = [int(token) for token in tokens]
        if ids[-1] != parent_id or len(set(ids)) != len(ids) or any(not 1 <= value <= 2147483647 for value in ids):
            raise ValueError()
        markers = ",".join(["%s"] * len(ids))
        cursor.execute("SELECT provider,subject_type,namespace,group_id FROM cf_sso_group_map WHERE provider=%s AND subject_type='dept' AND namespace=%s AND group_id IN (" + markers + ") FOR UPDATE", (provider, namespace, *ids))
        owned = cursor.fetchall()
        if any(row[:3] != (provider, "dept", namespace) for row in owned) or {row[3] for row in owned} != set(ids):
            raise ValueError()
        cursor.execute("SELECT group_id,parent_group_id FROM " + self.table + " WHERE group_id IN (" + markers + ") ORDER BY group_id FOR UPDATE", tuple(ids))
        actual = dict(cursor.fetchall())
        if len(actual) != len(ids) or any(actual.get(value) != (-1 if index == 0 else ids[index-1]) for index, value in enumerate(ids)):
            raise ValueError()
        return parent_id, paths[0][0]

    def _ensure(self, *, actor, provider, namespace, external_id, name, kind, parent):
        identifier(actor, maximum=225)
        identifier(provider, maximum=32)
        for value in (namespace, external_id, name):
            identifier(value)
        scopes = [{"type": "provider", "provider": provider, "external_id": provider},
                  {"type": "subject", "provider": provider, "namespace": namespace, "external_id": external_id}]
        try:
            with self.guard(actor, provider), scope_locks(self.connection, scopes):
                self.connection.begin()
                try:
                    with self.connection.cursor() as cursor:
                        cursor.execute("SELECT provider,subject_type,namespace,external_id,group_id,parent_external_id FROM cf_sso_group_map "
                                       "WHERE provider=%s AND subject_type=%s AND namespace=%s AND external_id=%s FOR UPDATE",
                                       (provider, kind, namespace, external_id))
                        rows = cursor.fetchall()
                        if len(rows) > 1 or (rows and (rows[0][:4] != (provider, kind, namespace, external_id) or rows[0][5] != parent)):
                            raise ValueError()
                        parent_id, parent_path = (0, None) if kind == "group" else (-1, None)
                        if kind == "dept":
                            cursor.execute("SELECT path FROM " + self.structure + " WHERE group_id=0 FOR UPDATE")
                            if parent is not None:
                                parent_id, parent_path = self._parent(cursor, provider, namespace, parent)
                        # Acquire native table metadata before engine inspection;
                        # even a fresh group must never escape rollback in MyISAM.
                        if rows:
                            group_id = rows[0][4]
                            cursor.execute("SELECT group_id,parent_group_id FROM " + self.table + " WHERE group_id=%s FOR UPDATE", (group_id,))
                            native = cursor.fetchall()
                            if (type(group_id) is not int or not 1 <= group_id <= 2147483647 or
                                    native != ((group_id, parent_id),)):
                                raise ValueError()
                            cursor.execute("SELECT id FROM cf_sso_group_map WHERE group_id=%s FOR UPDATE", (group_id,))
                            if len(cursor.fetchall()) != 1:
                                raise ValueError()
                        else:
                            cursor.execute("SELECT group_id FROM " + self.table + " WHERE group_id=0 FOR UPDATE")
                        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
                                       (self.native_schema, self.native_table))
                        if cursor.fetchall() != (("InnoDB",),):
                            raise ValueError()
                        if kind == "dept":
                            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name='GroupStructure'", (self.native_schema,))
                            if cursor.fetchall() != (("InnoDB",),):
                                raise ValueError()
                            if rows:
                                cursor.execute("SELECT path FROM " + self.structure + " WHERE group_id=%s FOR UPDATE", (group_id,))
                                expected = str(group_id) if parent_path is None else parent_path + ", " + str(group_id)
                                if cursor.fetchall() != ((expected,),):
                                    raise ValueError()
                        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_sso_group_map'")
                        if cursor.fetchall() != (("InnoDB",),):
                            raise ValueError()
                        if rows:
                            return group_id, False
                        now = int(time.time())
                        # CE's system-admin creation does not add a staff member.
                        # LAST_INSERT_ID avoids native name/timestamp ambiguity.
                        cursor.execute("INSERT INTO " + self.table + "(group_name,creator_name,timestamp,parent_group_id) VALUES(%s,'system admin',%s,%s)", (name, now, parent_id))
                        group_id = cursor.lastrowid
                        if type(group_id) is not int or not 1 <= group_id <= 2147483647:
                            raise ValueError()
                        if kind == "dept":
                            path = str(group_id) if parent_path is None else parent_path + ", " + str(group_id)
                            if len(path) > 1024:
                                raise ValueError()
                            cursor.execute("INSERT INTO " + self.structure + "(group_id,path) VALUES(%s,%s)", (group_id, path))
                        cursor.execute("INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name,parent_external_id,ctime,mtime) "
                                       "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)", (provider, kind, namespace, external_id, group_id, name, parent, now, now))
                        self.audit(cursor, dict(actor=actor, action="group.provision", provider=provider,
                                                namespace=namespace, external_id=external_id, group_id=group_id,
                                                subject_type=kind, parent_external_id=parent))
                    self.connection.commit()
                    return group_id, True
                finally:
                    self.connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError("PROJECTION_UNAVAILABLE", "Native group provisioning is unavailable", 503) from None


# Compatibility for the earlier internal flat-role adapter; no public API.
RoleGroupProvisioner = NativeGroupProvisioner
