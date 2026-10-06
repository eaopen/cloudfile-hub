# -*- coding: utf-8 -*-
"""Bounded completeness reconciliation for the legacy Meili index.

Pure algorithm code: no Django/seafile imports at module level, the same
convention ``cloudfile_ext.search.ops`` and ``cloudfile_ext.search.backfill``
follow, so counting, batching, threshold evaluation and stale selection stay
unit-testable on their own.

The forward pass walks one library's native tree with ``advance_page`` (bounded,
head-pinned) and asks the index whether every visited entry's deterministic
document id exists. Existence is resolved batch-wise through
``POST /indexes/<index>/documents/fetch`` so one native page of 100 entries
costs one index round trip, not 100. Nothing here ever writes to the index.
"""

from cloudfile_ext.search.ops import doc_id

#: Document ids per batch existence probe. Equal to the native page size, so a
#: visited page is normally resolved by exactly one index call.
BATCH_IDS = 100

#: Missing paths carried by the report. The full missing set is a count, never a
#: payload: a library that lost most of its documents would otherwise turn the
#: summary into a multi-megabyte response.
SAMPLE_MISSING_MAX = 20

#: Index documents examined per --stale page.
STALE_PAGE = 100

#: --max-stale-checks ceiling.
MAX_STALE_CHECKS = 100000


def coverage_ratio(indexed, native):
    """File coverage in [0, 1]; an empty native set is a complete pass."""
    if native <= 0:
        return 1.0
    return indexed / float(native)


def record_for(repo_id, path, object_type):
    """The per-entry observation the traversal callbacks hand back.

    Carries exactly what the existence probe needs; the document id stays the
    deterministic ``doc_id`` so a reconcile run and a backfill run always agree
    on which document a native path maps to.
    """
    return {'id': doc_id(repo_id, path), 'path': path, 'object_type': object_type}


class Reconciler(object):
    """Accumulates native/indexed/missing counts across traversal pages."""

    def __init__(self, repo_id, client, *, batch_ids=BATCH_IDS):
        self.repo_id = repo_id
        self.client = client
        self.batch_ids = batch_ids
        #: 'batch' while POST /documents/fetch works, 'per-document' after the
        #: probe (or a malformed batch response) says it does not.
        self.mode = 'batch'
        self.indexed_files = 0
        self.indexed_dirs = 0
        self.missing_files = 0
        self.missing_dirs = 0
        self.sample_missing = []

    def restore(self, state):
        """Rebuild counters from a validated checkpoint; missing means a fresh run."""
        self.indexed_files = state.get('indexed_files', 0)
        self.indexed_dirs = state.get('indexed_dirs', 0)
        self.missing_files = state.get('missing_files', 0)
        self.missing_dirs = state.get('missing_dirs', 0)
        self.sample_missing = [dict(row) for row in state.get('sample_missing', [])]

    def snapshot(self):
        """The counters a checkpoint must persist to stay resumable."""
        return {
            'indexed_files': self.indexed_files,
            'indexed_dirs': self.indexed_dirs,
            'missing_files': self.missing_files,
            'missing_dirs': self.missing_dirs,
            'sample_missing': [dict(row) for row in self.sample_missing],
        }

    def probe(self):
        """Whether the batch endpoint exists and returns the expected shape.

        One read-only call with no ids: it must answer a JSON object carrying an
        array of ``results``. Any failure (missing route, older Meilisearch,
        malformed body) switches the run to per-document GETs instead of
        aborting -- the fallback is slower but still correct.
        """
        try:
            response = self.client.fetch_documents([], limit=1)
        except Exception:
            self.mode = 'per-document'
            return self.mode
        if isinstance(response, dict) and isinstance(response.get('results'), list):
            self.mode = 'batch'
        else:
            self.mode = 'per-document'
        return self.mode

    def check_page(self, records):
        """Resolve one traversal page against the index and accumulate.

        Called synchronously from ``advance_page``'s write callback, so by the
        time the caller saves its checkpoint every visited entry has a settled
        answer and the checkpoint counters can never run ahead of the probe.
        """
        if not records:
            return
        existing = self._existing_ids([record['id'] for record in records])
        for record in records:
            found = record['id'] in existing
            if record['object_type'] == 'dir':
                if found:
                    self.indexed_dirs += 1
                else:
                    self.missing_dirs += 1
            else:
                if found:
                    self.indexed_files += 1
                else:
                    self.missing_files += 1
            if not found and len(self.sample_missing) < SAMPLE_MISSING_MAX:
                self.sample_missing.append(
                    {'path': record['path'], 'object_type': record['object_type']})

    def _existing_ids(self, document_ids):
        found = set()
        for start in range(0, len(document_ids), self.batch_ids):
            batch = document_ids[start:start + self.batch_ids]
            if self.mode == 'batch':
                found |= self._batch_lookup(batch)
            else:
                found |= self._get_lookup(batch)
        return found

    def _batch_lookup(self, batch):
        response = self.client.fetch_documents(batch, limit=len(batch))
        results = response.get('results') if isinstance(response, dict) else None
        if not isinstance(results, list):
            # A broken body is not proof that the documents are missing; resolve
            # this batch one by one and keep going.
            self.mode = 'per-document'
            return self._get_lookup(batch)
        found = {row['id'] for row in results
                 if isinstance(row, dict) and isinstance(row.get('id'), str)}
        total = response.get('total')
        # `limit` was len(batch), so a healthy response returns every match. If
        # the backend truncated anyway, only the ids it withheld are in doubt:
        # resolve exactly those by id instead of reporting them as missing.
        if isinstance(total, int) and total > len(found):
            for document_id in batch:
                if document_id not in found and self.client.document_exists(document_id):
                    found.add(document_id)
        return found

    def _get_lookup(self, batch):
        return {document_id for document_id in batch
                if self.client.document_exists(document_id)}


def stale_documents(client, repo_id, *, max_checks, path_exists, page_size=STALE_PAGE):
    """Index documents for ``repo_id`` whose native path no longer exists.

    Pages the index with a ``repo_id`` filter and a bounded field set, then asks
    the caller's ``path_exists(document)`` whether the native object is still
    there. ``max_checks`` is the hard bound on index documents examined, so a
    stale sweep never turns into an unbounded scan. Returns the checked count and
    the stale rows; read-only against the index.
    """
    stale = []
    checked = 0
    offset = 0
    while checked < max_checks:
        limit = min(page_size, max_checks - checked)
        response = client.documents_for_repo(repo_id, offset, limit)
        results = response.get('results') if isinstance(response, dict) else None
        if not isinstance(results, list) or not results:
            break
        for document in results:
            # A document without a usable path cannot be proven native; report
            # it as stale rather than silently dropping the row.
            path = document.get('path') if isinstance(document, dict) else None
            if not isinstance(path, str) or not path_exists(document):
                stale.append({'path': path,
                              'object_type': document.get('object_type')
                              if isinstance(document, dict) else None})
        checked += len(results)
        offset += len(results)
        if len(results) < limit:
            break
    return {'checked': checked, 'stale': stale}
