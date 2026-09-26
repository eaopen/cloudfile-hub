"""Synchronous session-guarded Hub bytes; not file-content authorization."""
from .session_authority import OIDCSessionAuthority
from .native_session import SESSION_REFERENCE_KEY
from ..common.errors import ContractError


class OIDCSessionStream:
    BLOCK = 65536
    MAX_SOURCE_CHUNK = 1048576

    def __init__(self, source, authority, request):
        if not isinstance(authority, OIDCSessionAuthority):
            raise ValueError("actual current session authority required")
        self.source = iter(source)
        self.authority, self.request = authority, request
        self.key = request.session.session_key
        self.reference = dict(request.session.get(SESSION_REFERENCE_KEY) or {})
        self.pending = memoryview(b"")
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            while not self.pending:
                # Source I/O must not keep a SQL/provider lock held.
                value = next(self.source)
                if not isinstance(value, bytes) or len(value) > self.MAX_SOURCE_CHUNK:
                    raise ContractError("IDENTITY_UNAVAILABLE", "Stream chunk is outside the supported limit", 503)
                self.pending = memoryview(value)
            if (self.request.session.session_key != self.key
                    or self.request.session.get(SESSION_REFERENCE_KEY) != self.reference):
                raise ContractError("AUTHENTICATION_REQUIRED", "Stream session changed", 401)
            chunk = self.pending[:self.BLOCK].tobytes()
            self.authority.check(self.request)
            self.pending = self.pending[len(chunk):]
            return chunk
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.closed:
            self.closed = True
            self.pending = memoryview(b"")
            close = getattr(self.source, "close", None)
            if callable(close):
                close()
