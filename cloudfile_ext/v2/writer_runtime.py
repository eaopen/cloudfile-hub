"""Probe the explicitly inventoried direct Go/C writer pairs for admin requests."""
from concurrent.futures import ThreadPoolExecutor
import time
from urllib.parse import urlsplit

import jwt
import requests
from django.conf import settings

FEATURES = ('checkout', 'protection')


def _probe(root, token):
    unknown = dict.fromkeys(FEATURES, 'unknown')
    try:
        url = urlsplit(root)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.query or url.fragment:
            return unknown
        with requests.get(root.rstrip('/') + '/internal/cf-writer-capabilities/v1',
                          headers={'Authorization': 'Bearer ' + token}, timeout=(1, 3),
                          allow_redirects=False) as response:
            if response.status_code != 200:
                return unknown
            data = response.json()
        if not isinstance(data, dict):
            return unknown
        return {key: ('ready' if data[key] else 'unavailable')
                if type(data.get(key)) is bool else 'unknown' for key in FEATURES}
    except (ValueError, requests.RequestException):
        return unknown


def writer_runtime():
    roots = getattr(settings, 'CLOUDFILE_WRITER_ROOTS', ())
    secret = getattr(settings, 'JWT_PRIVATE_KEY', '')
    if (not secret or not isinstance(roots, (list, tuple)) or not roots or
            any(not isinstance(root, str) or not root for root in roots)):
        return dict.fromkeys(FEATURES, 'unknown')
    token = jwt.encode({'iss': 'cloudfile-hub', 'aud': 'cf-writer-capabilities-v1',
                        'exp': int(time.time()) + 30}, secret, algorithm='HS256')
    with ThreadPoolExecutor(max_workers=min(8, len(roots))) as pool:
        observations = list(pool.map(lambda root: _probe(root, token), roots))
    result = {}
    for key in FEATURES:
        states = {entry[key] for entry in observations}
        result[key] = ('unavailable' if 'unavailable' in states else
                       'ready' if states == {'ready'} else 'unknown')
    return result
