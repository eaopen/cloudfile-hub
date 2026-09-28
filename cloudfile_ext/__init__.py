# -*- coding: utf-8 -*-
"""CloudFile extensions for Seahub.

Everything CloudFile adds to Seahub lives under this package. Only two upstream
files are patched (see BRANCHING.md in cloudfile-docker); all other behaviour is
reached through the hooks registered here, so that following upstream stays a
small, reviewable merge.

With every CF_ENABLE_* switch off this package must be a no-op: that property is
the P0 acceptance criterion and is what keeps upgrades cheap.
"""

default_app_config = 'cloudfile_ext.apps.CloudFileConfig'
