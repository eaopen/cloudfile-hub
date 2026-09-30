"""Strict, bounded native transport. Each invocation re-evaluates every path."""
import json
import time
from uuid import UUID

from .access import checked_path, unavailable

MAX_PATHS = 50
MAX_BYTES = 65536


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


class NativePermissionMany:
    def __init__(self, repo_id, username, rpc, hook, *, clock=time.monotonic):
        self.repo_id, self.username = str(UUID(repo_id)), username
        if not isinstance(username, str) or not username or '\x00' in username or len(username.encode()) > 255:
            raise unavailable()
        self.rpc, self.hook, self.clock = rpc, hook, clock
        self.deadline = clock() + 10

    def _request(self, paths):
        return json.dumps(dict(version=1, repo_id=self.repo_id, user=self.username,
            paths=paths), ensure_ascii=False, separators=(',', ':'))

    def __call__(self, paths):
        try:
            # Search deduplicates; this adapter also supports duplicate slots in
            # the native contract, without conflating them in a response map.
            paths = [checked_path(path) for path in paths]
            groups, group = [], []
            for path in paths:
                candidate = group + [path]
                if len(candidate) > MAX_PATHS or len(self._request(candidate).encode()) > MAX_BYTES:
                    if not group:
                        raise ValueError("oversized path")
                    groups.append(group)
                    group = [path]
                else:
                    group = candidate
            if group:
                groups.append(group)
            permissions = []
            for group in groups:
                request = self._request(group)
                if len(request.encode()) > MAX_BYTES or self.clock() >= self.deadline:
                    raise ValueError("batch budget exceeded")
                raw = self.rpc(request)
                if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES * 8:
                    raise ValueError("invalid response envelope")
                response = json.loads(raw, object_pairs_hook=_object)
                if (not isinstance(response, dict) or
                        set(response) != {'version', 'repo_id', 'user', 'items'} or
                        type(response['version']) is not int or response['version'] != 1 or
                        response['repo_id'] != self.repo_id or response['user'] != self.username or
                        not isinstance(response['items'], list) or len(response['items']) != len(group)):
                    raise ValueError("response context or cardinality mismatch")
                # Validate the whole response before applying any Hub hook.
                # Exact positional path matching rejects missing/extra/reordered
                # or duplicate results, including malformed readable defaults.
                for path, item in zip(group, response['items']):
                    if (not isinstance(item, dict) or set(item) != {'path', 'permission'} or
                            item['path'] != path or item['permission'] not in (None, 'r', 'rw')):
                        raise ValueError("invalid path decision")
                for path, item in zip(group, response['items']):
                    permission = item['permission']
                    if permission is not None:
                        permission = self.hook(self.username, self.repo_id, path, permission)
                    permissions.append(permission if permission in ('r', 'rw') else None)
                if self.clock() >= self.deadline:
                    raise ValueError("batch budget exceeded")
            return permissions
        except Exception:
            # No partial page and no transport-to-scalar fallback on deployment
            # skew, RPC/provider exceptions, malformed replies or timeout.
            raise unavailable() from None
