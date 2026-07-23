# -*- coding: utf-8 -*-
"""CloudFile default settings.

conf/seahub_settings.py does ``from cloudfile_ext.settings_defaults import *``
before applying any operator overrides, so everything here is a default that
the compose .env can override.

Note the EXTRA_ prefix on the list settings: Seahub's ``load_local_settings``
(seahub/settings.py) *appends* any EXTRA_<NAME> to the existing <NAME>, which
is how cloudfile_ext gets installed without patching settings.py.
"""

# -- extension registration ----------------------------------------------

EXTRA_INSTALLED_APPS = [
    'cloudfile_ext',
]

# -- feature switches (all off by default) --------------------------------

CF_ENABLE_SSO = False
CF_ENABLE_DIR_ACL = False
CF_ENABLE_AUDIT = False
CF_ENABLE_METADATA = False
CF_ENABLE_TAGS = False
CF_ENABLE_MEILISEARCH = False
CF_ENABLE_ONLYOFFICE = False
CF_ENABLE_CHECKOUT = False
CF_ENABLE_S3_STORAGE = False
CF_ENABLE_EXTERNAL_SOURCES = False

# -- database --------------------------------------------------------------

# cf_* tables live in seafile-db rather than seahub-db because seaf-server and
# the Go fileserver only ever connect to ccnet-db and seafile-db; putting them
# anywhere else would make them unreadable to the layer that has to enforce
# the rules. cloudfile_ext.db_router points cf_* models at this alias.
#
# The connection itself is assembled in CloudFileConfig.ready(), not here:
# seahub_settings.py is imported as a plain module, so it has no DATABASES to
# add an entry to. These scalars are what the docker bootstrap writes.
CF_DATABASE_ALIAS = 'cloudfile'
CF_DATABASE_NAME = ''
CF_DATABASE_USER = ''
CF_DATABASE_PASSWORD = ''
CF_DATABASE_HOST = ''
CF_DATABASE_PORT = '3306'

# Seconds to cache a repo's ACL rules in-process. Kept short because the
# authoritative enforcement is in seafile-server; this cache only spares the
# Hub a query per permission check.
CF_ACL_CACHE_TTL = 30
