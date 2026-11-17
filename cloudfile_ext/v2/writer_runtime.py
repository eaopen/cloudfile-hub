"""Check the native writer using Seahub's existing internal Fileserver route."""
import time
from urllib.parse import urlsplit

import jwt
import requests
from django.conf import settings
from seahub.utils import CLUSTER_MODE, get_inner_fileserver_root

FEATURES = ('checkout', 'protection')


def writer_runtime():
    unknown = dict.fromkeys(FEATURES, 'unknown')
    root = get_inner_fileserver_root()
    secret = getattr(settings, 'JWT_PRIVATE_KEY', '')
    if not isinstance(root, str) or not secret:
        return unknown
    try:
        address = urlsplit(root)
        if address.scheme not in ('http', 'https') or not address.hostname:
            return unknown
        # A cluster or remote route may distribute writes. One response can
        # establish a missing prerequisite, but cannot attest every writer.
        direct = not CLUSTER_MODE and address.hostname in ('127.0.0.1', 'localhost', '::1')
        token = jwt.encode({'iss': 'cloudfile-hub', 'aud': 'cf-writer-capabilities-v1',
                            'exp': int(time.time()) + 30}, secret, algorithm='HS256')
        with requests.get(root.rstrip('/') + '/internal/cf-writer-capabilities/v1',
                          headers={'Authorization': 'Bearer ' + token}, timeout=(1, 3),
                          allow_redirects=False) as response:
            if response.status_code != 200:
                return unknown
            data = response.json()
        if not isinstance(data, dict):
            return unknown
        result = unknown.copy()
        for key in FEATURES:
            if data.get(key) is False:
                result[key] = 'unavailable'
            elif data.get(key) is True and direct:
                result[key] = 'ready'
        return result
    except (ValueError, requests.RequestException):
        return unknown
