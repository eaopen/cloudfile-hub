"""Compatibility import for the retired bounded-search URL.

Current authenticated search is implemented exclusively by the V2 SearchQuery
endpoint. Do not restore legacy ACL snapshots, alternate subject resolution,
cf_dir_admin, or a second search authorization engine here.
"""
from cloudfile_ext.v2.search.http import SearchQuery as BoundedSearch
