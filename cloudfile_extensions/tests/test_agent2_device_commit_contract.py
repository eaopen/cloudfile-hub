"""No database needed: challenge binds the current guard, session & digest."""
import hashlib
import unittest

from cloudfile_extensions.local_edit.commit_contract import bind_request, validate_request
from cloudfile_extensions.common.errors import ContractError


class DeviceCommitContractTest(unittest.TestCase):
    def setUp(self):
        self.request = dict(
            session_id="11111111-1111-4111-8111-111111111111",
            device_id="22222222-2222-4222-8222-222222222222",
            intent_id="33333333-3333-4333-8333-333333333333",
            guard_id="44444444-4444-4444-8444-444444444444",
            generation="3", credential_epoch="2", token="a" * 64,
            base_file_id="b" * 40, content_digest="c" * 64,
            snapshot_size=17000000, action="commit")
        digest = hashlib.sha256(self.request["token"].encode()).hexdigest()
        self.snapshot = dict(
            mode="exclusive-edit", resource_uid="55555555-5555-4555-8555-555555555555",
            resource={"kind":"file", "repo_id":"66666666-6666-4666-8666-666666666666",
                      "path":"/design/sample.dwg"},
            lease={"fencing":"3","token_digest":digest})
        self.guard=dict(mode="checkout", credential_active=True,
            owner_native_user="engineer@example.test",
            guard_id=self.request["guard_id"], generation=3,
            credential_epoch=2, base_file_id=self.request["base_file_id"],
            proof_digest=digest, pending_intent=None)
        self.row=[None]*10
        self.row[3]=5
        self.row[9]=7

    def digest(self, request=None, snapshot=None, guard=None):
        return bind_request(request or self.request,snapshot=snapshot or self.snapshot,
            session_row=self.row,edit_guard=guard or self.guard,
            current_native="engineer@example.test")

    def test_valid_bounded_manual_one_file(self):
        self.assertIs(validate_request(self.request),self.request)
        self.assertRegex(self.digest(),r"^[0-9a-f]{64}$")
        for field, value in (
            ("action","auto-upload"),
            ("snapshot_size", 128*1024*1024+1),
            ("content_digest","x"*64),
            ("generation","03"),
        ):
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_request({**self.request,field:value})
        with self.assertRaises(ContractError):
            validate_request({**self.request, "actor":"somebody"})

    def test_device_proof_cannot_be_reused_for_another_intent_or_content(self):
        base=self.digest()
        for field,value in (
            ("intent_id","77777777-7777-4777-8777-777777777777"),
            ("content_digest","d"*64),
            ("action","checkin"),
            ("snapshot_size",32000000),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(base,self.digest({**self.request,field:value}))
        changed=dict(self.snapshot)
        changed["resource"]={**self.snapshot["resource"],"path":"/another.dwg"}
        self.assertNotEqual(base,self.digest(snapshot=changed))

    def test_changed_guard_or_released_checkout_fails_before_authority(self):
        for field,value in (
            ("mode","file-lock"),("pending_intent","77777777-7777-4777-8777-777777777777"),
            ("owner_native_user","someone-else@example.test"),
            ("credential_active",False),("base_file_id","d"*40),
        ):
            with self.subTest(field=field),self.assertRaises(ContractError):
                self.digest(guard={**self.guard,field:value})
        with self.assertRaises(ContractError):
            self.digest(snapshot={**self.snapshot,"mode":"optimistic-edit"})


if __name__=="__main__":
    unittest.main()
