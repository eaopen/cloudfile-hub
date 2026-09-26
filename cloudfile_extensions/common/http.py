"""Bounded HTTPS JSON transport for deployment-owned directory/IdP addresses."""

import json
import os
from urllib.parse import urlsplit

import requests

from .errors import ContractError


def trusted_https_url(value):
    if not isinstance(value, str):
        raise ValueError("service URL must be HTTPS")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.fragment or parsed.query):
        raise ValueError("service URL must be a fixed HTTPS address without credentials or query")
    return value


def read_json_response(response, *, maximum_bytes=1024 * 1024):
    try:
        if response.status_code == 404:
            raise ContractError("UPSTREAM_NOT_FOUND", "Required upstream record does not exist", 404)
        if response.status_code != 200:
            raise ContractError("UPSTREAM_UNAVAILABLE", "Required service is unavailable", 503)
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/json", "application/jwk-set+json"}:
            raise ValueError()
        data = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            data.extend(chunk)
            if len(data) > maximum_bytes:
                raise ValueError()
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, requests.RequestException):
        raise ContractError("UPSTREAM_UNAVAILABLE", "Invalid service response", 503) from None
    finally:
        response.close()


class HttpsJsonClient:
    def __init__(self, *, session=None, maximum_bytes=1024 * 1024, ca_bundle=None):
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 1024 * 1024:
            raise ValueError("invalid HTTPS response size limit")
        self.session = requests.Session() if session is None else session
        # No environment proxy or netrc credentials on this trusted machine channel.
        self.session.trust_env = False
        self.maximum_bytes = maximum_bytes
        if ca_bundle is not None and (not isinstance(ca_bundle, str) or not os.path.isfile(ca_bundle)):
            raise ValueError("TLS CA bundle must be a trusted deployment file")
        self.verify = True if ca_bundle is None else ca_bundle

    def get(self, url, *, headers=None):
        trusted_https_url(url)
        try:
            response = self.session.get(url, headers=headers, allow_redirects=False,
                                        timeout=(3, 10), stream=True, verify=self.verify)
        except requests.RequestException:
            raise ContractError("UPSTREAM_UNAVAILABLE", "Required service is unavailable", 503) from None
        return read_json_response(response, maximum_bytes=self.maximum_bytes)
