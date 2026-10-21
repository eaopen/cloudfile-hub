"""Both OIDC multipart and device raw bytes use this bounded writer."""
from io import BytesIO
import hashlib
import unittest
from cloudfile_extensions.local_edit.shared_staging import stage_chunks


class SharedStagingTests(unittest.TestCase):
    def test_browser_and_agent_identical_staging(self):
        parts=[b"First CAD",b"\\x00" * 32,b"Last part"]
        payload=b"".join(parts)
        expected=hashlib.sha256(payload).hexdigest()
        import tempfile
        with tempfile.TemporaryFile() as web:
            result=stage_chunks(web,parts,expected_size=len(payload),
                                max_bytes=512*1024*1024)
            web.seek(0)
            self.assertEqual(result,expected)
            self.assertEqual(web.read(),payload)
        with tempfile.TemporaryFile() as agent:
            result=stage_chunks(agent,parts,expected_size=len(payload),
                max_bytes=128*1024*1024,digest=expected,
                protect_snapshot=True)
            agent.seek(0)
            self.assertEqual(agent.read(),payload)
            self.assertEqual(result,expected)

    def test_extra_or_wrong_bytes_rejected(self):
        for content,size,expect in (([b"bad"],3,"invalid"),
                ([b"wrong"],5,"0"*64),([b"short"],10,None)):
            import tempfile
            with tempfile.TemporaryFile() as stream:
                with self.assertRaises(Exception):
                    stage_chunks(stream,content,expected_size=size,
                        max_bytes=128*1024*1024,digest=expect)
