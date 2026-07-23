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
# the Go fileserver only ever connect to ccnet-db and seafile-db; putting the
# ACL anywhere else would make it unreadable to the layer that has to enforce
# it. cloudfile_ext.db_router points cf_* models at this alias.
CF_DATABASE_ALIAS = 'cloudfile'

# Seconds to cache a repo's ACL rules in-process. Kept short because the
# authoritative enforcement is in seafile-server; this cache only spares the
# Hub a query per permission check.
CF_ACL_CACHE_TTL = 30
