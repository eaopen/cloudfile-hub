"""One bounded, fsynced staging primitive for OIDC Web and Agent uploads.

Authentication, content source and publication authorization remain distinct.
This helper cannot publish a cloud file, accept an arbitrary local path or
grant a user/device permission.
"""
import hashlib
import hmac
import os

from ..common.errors import invalid


def stage_chunks(output, chunks, *, expected_size, max_bytes, digest=None,
                 protect_snapshot=False):
    if (type(expected_size) is not int or type(max_bytes) is not int or
            expected_size < 0 or expected_size > max_bytes):
        raise invalid("Bounded upload size required")
    counter=0
    checksum=hashlib.sha256()
    for part in chunks:
        if not isinstance(part, bytes):
            raise invalid("Binary upload chunks required")
        counter+=len(part)
        if counter>expected_size:
            raise invalid("Upload stream exceeds declared size")
        output.write(part)
        checksum.update(part)
    if counter!=expected_size:
        raise invalid("Incomplete file content")
    actual=checksum.hexdigest()
    if digest is not None and not hmac.compare_digest(actual,digest):
        raise invalid("Upload does not match original immutable snapshot")
    output.flush()
    os.fsync(output.fileno())
    if protect_snapshot:
        os.fchmod(output.fileno(),0o400)
    return actual
