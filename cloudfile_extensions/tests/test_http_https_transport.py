"""First-class HTTP/HTTPS canonical origin and browser cookie compatibility."""
import unittest

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY="http-compat-fixture",ALLOWED_HOSTS=["testserver"],
                       DEFAULT_CHARSET="utf-8")
from django.http import HttpResponse
from django.test import RequestFactory

from cloudfile_extensions.local_edit.private_http import canonical_http, transport_allowed
from cloudfile_extensions.identity.browser_binding import (
    BrowserLoginBindings,binding_cookie,request_binding)


class RedisFixture:
    def set(self,key,value,**kwargs):return True
    def delete(self,key):return 1


class HTTPTransportTests(unittest.TestCase):
    def test_http_https_canonical_and_request_host_restriction(self):
        for origin in ("http://cloudfile.internal","http://10.12.1.157:8092",
                       "https://cloudfile.internal","https://cloudfile.internal:9443"):
            self.assertTrue(canonical_http(origin),origin)
        for bad in ("ftp://cloudfile.internal","http://user@cloudfile.internal",
                    "http://cloudfile.internal/path","http://cloudfile.internal/",
                    "http://CLOUDFILE.internal","http://cloudfile.internal?x=1",
                    "http://cloudfile.internal:99999"):
            self.assertFalse(canonical_http(bad),bad)
        for secure in (False,True):
            req=RequestFactory().get("/",secure=secure,HTTP_HOST="testserver")
            self.assertTrue(transport_allowed(req))
        self.assertFalse(transport_allowed(
            RequestFactory().get("/",secure=False,HTTP_HOST="evil.invalid")))

    def test_http_browser_binding_cookie_roundtrip_without_secure_flag(self):
        for secure in (False,True):
            request=RequestFactory().get("/",secure=secure)
            response=HttpResponse()
            bindings=BrowserLoginBindings(RedisFixture())
            issued=bindings.rotate(request,response)
            key=binding_cookie(request)
            self.assertIn(key,response.cookies)
            self.assertEqual(bool(response.cookies[key]["secure"]),secure)
            self.assertTrue(bool(response.cookies[key]["httponly"]))
            self.assertEqual(response.cookies[key]["samesite"],"Lax")
            new=RequestFactory().get("/",secure=secure,
                                     HTTP_COOKIE=key+"="+issued)
            self.assertEqual(request_binding(new),issued)
            clear=HttpResponse()
            bindings.clear(issued,clear,request=new)
            self.assertIn(key,clear.cookies)
            self.assertEqual(bool(clear.cookies[key]["secure"]),secure)
