# -*- coding: utf-8 -*-
"""Route cf_* models to seafile-db.

The ACL tables have to be readable by seaf-server (C) and the Go fileserver,
neither of which connects to seahub-db. They therefore live in seafile-db and
are created by cloudfile-server's scripts/sql, not by a Django migration --
the models are declared ``managed = False`` and this router only decides which
connection they use.

Install by adding to seahub_settings.py::

    DATABASE_ROUTERS = ['cloudfile_ext.db_router.CloudFileRouter']
"""

from django.conf import settings


def _alias():
    return getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')


class CloudFileRouter(object):

    #: Apps whose models live in seafile-db.
    app_labels = {'cloudfile_ext'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return _alias()
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return _alias()
        return None

    def allow_relation(self, obj1, obj2, **hints):
        # cf_* tables carry repo ids and emails as plain columns rather than
        # foreign keys precisely because they span databases, so there is
        # never a legitimate cross-database relation to allow.
        labels = {obj1._meta.app_label, obj2._meta.app_label}
        if labels & self.app_labels:
            return labels <= self.app_labels
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.app_labels:
            # Owned by cloudfile-server/scripts/sql, never by manage.py migrate.
            return False
        if db == _alias():
            return False
        return None
