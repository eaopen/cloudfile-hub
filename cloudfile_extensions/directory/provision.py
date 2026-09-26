"""Atomic flat-role group creation and mapping on one MySQL connection.

Trusted internal adapter only; no HTTP registration or readiness grant. Native
schema/table are deployment configuration, not request fields. Departments and
membership publication require their own complete native coordination.
"""
import time

from ..common.errors import ContractError
from ..common.validation import identifier
from ..jobs.authority import scope_locks


class RoleGroupProvisioner:
    def __init__(self, connection, *, native_schema, management_guard, audit_hook,
                 native_table="Group"):
        if not connection.get_autocommit() or not callable(management_guard) or not callable(audit_hook):
            raise ValueError("dedicated connection, management guard and transactional audit are required")
        identifier(native_schema, maximum=64)
        identifier(native_table, maximum=64)
        self.connection = connection
        self.native_schema, self.native_table = native_schema, native_table
        self.table = "`" + native_schema.replace("`", "``") + "`.`" + native_table.replace("`", "``") + "`"
        self.guard, self.audit = management_guard, audit_hook

    def ensure(self, *, actor, provider, namespace, external_id, name):
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
                        cursor.execute("SELECT provider,subject_type,namespace,external_id,group_id FROM cf_sso_group_map "
                                       "WHERE provider=%s AND subject_type='group' AND namespace=%s AND external_id=%s FOR UPDATE",
                                       (provider, namespace, external_id))
                        rows = cursor.fetchall()
                        if len(rows) > 1 or (rows and rows[0][:4] != (provider, "group", namespace, external_id)):
                            raise ValueError()
                        # Acquire native table metadata before engine inspection;
                        # even a fresh group must never escape rollback in MyISAM.
                        if rows:
                            group_id = rows[0][4]
                            cursor.execute("SELECT group_id,parent_group_id FROM " + self.table + " WHERE group_id=%s FOR UPDATE", (group_id,))
                            native = cursor.fetchall()
                            if (type(group_id) is not int or not 1 <= group_id <= 2147483647 or
                                    native != ((group_id, 0),)):
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
                        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_sso_group_map'")
                        if cursor.fetchall() != (("InnoDB",),):
                            raise ValueError()
                        if rows:
                            return group_id, False
                        now = int(time.time())
                        # CE's system-admin creation does not add a staff member.
                        # LAST_INSERT_ID avoids native name/timestamp ambiguity.
                        cursor.execute("INSERT INTO " + self.table + "(group_name,creator_name,timestamp,parent_group_id) VALUES(%s,'system admin',%s,0)", (name, now))
                        group_id = cursor.lastrowid
                        if type(group_id) is not int or not 1 <= group_id <= 2147483647:
                            raise ValueError()
                        cursor.execute("INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name,ctime,mtime) "
                                       "VALUES(%s,'group',%s,%s,%s,%s,%s,%s)", (provider, namespace, external_id, group_id, name, now, now))
                        self.audit(cursor, dict(actor=actor, action="group.provision", provider=provider,
                                                namespace=namespace, external_id=external_id, group_id=group_id))
                    self.connection.commit()
                    return group_id, True
                finally:
                    self.connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError("PROJECTION_UNAVAILABLE", "Native group provisioning is unavailable", 503) from None
