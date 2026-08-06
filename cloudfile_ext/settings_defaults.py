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
CF_ENABLE_SEARCH = False
CF_ENABLE_FILE_PREVIEW = False
CF_ENABLE_ONLYOFFICE = False
CF_ENABLE_FILE_LOCK = False
CF_ENABLE_WATCH = False
CF_ENABLE_CONVERT_EXPORT = False
CF_ENABLE_CHECKOUT = False
CF_ENABLE_LOCAL_APP = False
CF_ENABLE_S3_STORAGE = False
CF_ENABLE_EXTERNAL_SOURCES = False

# -- providers -------------------------------------------------------------

# Which implementation answers each pluggable job. Empty means "native CE
# behaviour"; a name must match something a capability registered, or the
# first use raises UnknownProvider rather than silently falling back.
#
# The setting name is derived from the kind (cloudfile_ext.providers), so a
# capability that declares a new kind needs no edit here -- these two are
# spelled out only because operators set them.
#
# CF_PROVIDER_SEARCH left empty (the default) means "native": whichever
# backend seafevents.conf configures under [SEASEARCH] or [INDEX FILES]
# (SeaSearch or Elasticsearch) answers queries exactly as it does on upstream
# CE. For SeaSearch specifically that is upstream's own
# `elif HAS_FILE_SEASEARCH` branch in seahub.api2.views.Search.get(), which
# does not go through search_files() at all -- there is no 'seasearch'
# provider name to select, because that path needs no CloudFile code (see
# cloudfile_ext.search's module docstring). Set this to 'meilisearch' to route
# queries to cloudfile_ext.search.backends.meilisearch instead.
CF_PROVIDER_SEARCH = ''            # '' (native SeaSearch/ES) or 'meilisearch'
CF_PROVIDER_ACL_RULE_SOURCE = ''   # e.g. 'local-db', 'external-service'
CF_PROVIDER_SSO_DIRECTORY = ''     # e.g. 'static', 'external-service'

# -- external services -----------------------------------------------------

# Per-service settings are CF_SERVICE_<NAME>_{URL,SECRET,TIMEOUT,RETRIES,
# ON_FAILURE}; see cloudfile_ext.external_service. Nothing is configured by
# default, and a service is never consulted on the synchronous permission
# path -- rules are pulled into cf_* tables and enforced from there.

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

# -- SSO directory mapping -------------------------------------------------
#
# Login itself is upstream's (ENABLE_OAUTH / ENABLE_ADFS_LOGIN / ENABLE_CAS,
# all present in CE and none of them Pro-gated). These settings govern only the
# part upstream does not do: mirroring an organisation's groups into Seafile.

# Account that owns the groups the sync creates. No default on purpose --
# picking one silently would attach every synced group to whoever happens to
# sort first. Sync refuses to run until this names a real account.
CF_SSO_GROUP_OWNER = ''

# Seconds between full syncs, run by cf-worker. The webhook
# (api/v2.1/cloudfile/sso/directory-webhook/) is what makes changes apply in
# seconds; this interval is the floor when nothing pushes.
CF_SSO_SYNC_INTERVAL = 600

# Refuse a sync that would drop more than this share of managed memberships in
# one tick. A truncated or half-failed directory feed looks exactly like a mass
# departure, and only one of those readings is recoverable. Set to '' to lift
# the ceiling -- do that deliberately, for one real reorganisation, not as a
# standing configuration.
CF_SSO_MAX_REMOVAL_RATIO = 0.5

# Groups for CF_PROVIDER_SSO_DIRECTORY = 'static': a list of
# {'external_id': ..., 'name': ..., 'members': [login, ...]}.
CF_SSO_DIRECTORY_STATIC = []

# -- search: meilisearch backend --------------------------------------------
#
# Only consulted when CF_PROVIDER_SEARCH = 'meilisearch'. The default
# (CF_PROVIDER_SEARCH = '') needs none of this -- SeaSearch/Elasticsearch are
# configured entirely through seafevents.conf, which cloudfile-docker's
# bootstrap writes from CF_ENABLE_SEARCH and CF_SEASEARCH_TOKEN.

CF_MEILISEARCH_URL = 'http://meilisearch:7700'
CF_MEILISEARCH_API_KEY = ''
# HTTP timeout for a single Meilisearch call. Kept short: a slow search
# backend must not turn into a slow page load, and Seahub's own search view
# already wraps this in a bare except that renders an empty result page.
CF_MEILISEARCH_TIMEOUT = 5

# How often cf-worker looks for new commits to index, in seconds.
CF_SEARCH_INDEX_INTERVAL = 60

# -- external sources -------------------------------------------------------
#
# Container paths a source root may live under. An external source is an
# SMB/NFS share the operator mounted on the host and bind-mounted here, so this
# is the boundary between "a share ops chose to expose" and "any path in the
# container".
#
# The default is deliberately restrictive rather than empty: an empty allow-list
# would let the admin API register / as an external source, and a security
# property that only holds when the operator configured it correctly is not one
# worth shipping. Widen it only to prefixes that contain nothing but mounts --
# never '/'.
#
# Containment against this list is re-checked on every access, not just at
# registration. The share is writable by whoever uses the NAS, and a symlink
# added after registration would otherwise widen what is reachable. See
# cloudfile_ext/external_sources/paths.py and docs/external-sources.md.
CF_EXTERNAL_SOURCES_ROOTS = ['/shared/external']

# Files at or under this size (in bytes) whose extension is in the plain-text
# set (cloudfile_ext.search.indexer.TEXT_EXTENSIONS) get their content indexed
# alongside filename/path/metadata. Larger or non-text files are indexed by
# metadata only -- content extraction for office/PDF formats is what SeaSearch
# already does through seafevents; re-doing it here would duplicate that
# pipeline for the one backend that exists specifically for sites that are not
# running SeaSearch. See docs/search.md.
CF_SEARCH_INDEX_TEXT_MAX_BYTES = 1024 * 1024

# -- file actions ----------------------------------------------------------

# Native previews remain upstream URLs; this list only decides which files get
# a CloudFile action entry point around that existing renderer.
CF_FILE_ACTION_PREVIEW_EXTENSIONS = (
    'pdf', 'txt', 'md', 'markdown', 'csv', 'json', 'xml', 'html', 'htm',
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp3', 'mp4', 'webm',
    'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'ods', 'odp',
)
CF_FILE_ACTION_OFFICE_EXTENSIONS = (
    'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'ods', 'odp',
    'csv', 'pdf',
)

# Native Messaging agents receive short-lived, single-file capabilities. A
# local write action remains unavailable until the seafile-server lock
# provider is present; an advisory Hub-only checkout would be unsafe.
CF_LOCAL_APP_SESSION_TTL = 300
