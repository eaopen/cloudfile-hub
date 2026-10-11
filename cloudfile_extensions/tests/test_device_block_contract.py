"""Fail-closed per-device CDC plan validation without a native runtime."""
import hashlib
import json
import unittest

from cloudfile_extensions.local_edit.block_contract import validate_plan


class DeviceBlockContractTests(unittest.TestCase):
    def setUp(self):
        self.data = [b"A"*8, b"B"*7, b"A"*8]
        self.ids = [hashlib.sha1(data).hexdigest() for data in self.data]
        self.size = sum(map(len, self.data))
        raw = json.dumps({"block_ids": self.ids, "size": self.size, "type": 1,
                          "version": 1}, sort_keys=True)
        self.value = dict(
            file_id=hashlib.sha1(raw.encode()).hexdigest(), size=self.size,
            sha256=hashlib.sha256(b"".join(self.data)).hexdigest(),
            blocks=[dict(id=id, size=len(data))
                    for id, data in zip(self.ids, self.data)])
        self.grant = dict(snapshot_size=self.size,
                          content_digest=self.value["sha256"])

    def test_native_seafile_v1_id_with_ordered_repeated_block(self):
        encoded, ordered, lengths = validate_plan(self.value, self.grant)
        self.assertEqual(ordered, self.ids)
        self.assertEqual(lengths[self.ids[0]], 8)
        self.assertEqual(len(lengths), 2)
        self.assertEqual(json.loads(encoded), self.value)

    def test_wrong_file_id_digest_size_block_or_extra_field_refused(self):
        cases = [
            dict(file_id="a"*40),
            dict(sha256="b"*64),
            dict(size=self.size+1),
            dict(blocks=[self.value["blocks"][1],self.value["blocks"][0],self.value["blocks"][2]]),
            dict(blocks=self.value["blocks"]+[dict(id="0"*40,size=1)]),
            dict(blocks=[dict(id=self.ids[0],size=9),
                         self.value["blocks"][1],self.value["blocks"][2]]),
            dict(blocks=[dict(id=self.ids[0],size=8),
                         self.value["blocks"][1],dict(id=self.ids[0],size=9)]),
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_plan({**self.value, **change},self.grant)
        for grant in (
            dict(snapshot_size=self.size+2,content_digest=self.value["sha256"]),
            dict(snapshot_size=self.size,content_digest="0"*64),
        ):
            with self.assertRaises(ValueError):
                validate_plan(self.value,grant)
        with self.assertRaises(ValueError):
            validate_plan({**self.value,"extra":"untrusted"},self.grant)

    def test_empty_and_bad_block_ids_refused(self):
        for bad in (
            [], [dict(id="f"*40,size=0)], [dict(id="F"*40,size=3)],
            [dict(id="f"*40,size=11*1024*1024)],
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_plan({**self.value,"blocks":bad},self.grant)


if __name__ == "__main__":
    unittest.main()
