# -*- coding: utf-8 -*-
"""CloudFile URL patterns.

Assembled from the registry rather than written out by hand, so a new
capability adds routes by calling ``registry.register_urls()`` in its
``register()`` and never touches this file.

seahub/utils/rooturl.py prepends these to Seahub's own patterns, which lets a
CloudFile route shadow a native endpoint when it has to.
"""

from cloudfile_ext.registry import registry

urlpatterns = list(registry.urls)
