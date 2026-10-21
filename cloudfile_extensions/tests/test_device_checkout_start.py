"""Browser retries never change Checkout proof or expose it to the URI."""
import unittest

from cloudfile_extensions.local_edit.checkout_credential import deterministic_checkout_token

class CheckoutIdentityTests(unittest.TestCase):
    def test_idempotent_browser_checkout_is_scoped_to_native_actor_and_device(self):
        base=dict(provider="etech",actor="employee-7",holder="verified-oidc-session",
                  reference=dict(repo_id="11111111-1111-4111-8111-111111111111",
                                 path="/design/drawing.dwg",kind="file"),
                  device_id="22222222-2222-4222-8222-222222222222",
                  base_file_id="a"*40,request_key="checkout-operation-001")
        secret=b"confidential-current-deployment-secret"
        token=deterministic_checkout_token(secret,**base)
        self.assertEqual(token,deterministic_checkout_token(secret,**base))
        self.assertEqual(len(token),64)
        self.assertRegex(token,r"^[0-9a-f]{64}$")
        for changed in (
            dict(actor="another-user"),
            dict(holder="another-oidc-session"),
            dict(device_id="33333333-3333-4333-8333-333333333333"),
            dict(request_key="another-operation"),
            dict(base_file_id="b"*40),
            dict(reference={**base["reference"],"path":"/other.dwg"}),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(token,deterministic_checkout_token(secret,**{**base,**changed}))
        self.assertNotEqual(token,deterministic_checkout_token(b"rotated-deployment-secret-1234567",**base))

if __name__ == "__main__":
    unittest.main()
