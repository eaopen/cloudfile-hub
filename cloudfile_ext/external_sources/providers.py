# -*- coding: utf-8 -*-
"""What an external source backend has to implement.

Registered with ``registry.register_external_source_provider(source_type,
provider)`` -- keyed by type, and deliberately neither a chain nor a
``register_provider(kind, ...)``:

* Not a chain, because a chain asks "who wants to participate?" and a source is
  answered by exactly one backend -- the one whose type it was registered with.
* Not a provider kind, because kinds are *interchangeable* implementations of
  one job with one selected by ``CF_PROVIDER_<KIND>``. Here ``local-path`` and
  a future ``smb`` coexist in one deployment, each serving its own sources.
  There is nothing to select.

Three rules, each of which exists because breaking it is a real failure mode
rather than a style violation:

**A backend never decides who may read.** It answers "what is at this path".
Authorisation is cloudfile_ext.external_sources.service, once, for every
backend. Same reasoning as the search provider contract: a backend that also
has to implement scoping is a backend that can leak by forgetting to.

**A backend validates containment itself.** It may not assume the caller
sanitised the path -- ``open_file`` is reached directly from the download
endpoint. Use cloudfile_ext.external_sources.paths; do not hand-roll it.

**"Cannot read" raises SourceError; it never returns empty.** An unreachable
NAS and an empty directory are indistinguishable to the caller, and only one
of them is a fact about the data. Same rule as sso/directory.py's
DirectoryError, and it is the failure mode that made that rule explicit there.
"""

import collections


class SourceError(Exception):
    """The source could not be read, or answered with something unusable."""


class SourceNotFound(SourceError):
    """The path does not exist in the source.

    A subclass rather than a return value of None so that a caller which does
    not care can let it propagate to a 404, while the listing code can catch it
    specifically -- without either of them mistaking it for an empty directory.
    """


#: One directory entry. Deliberately the smallest set that a file browser and
#: an incremental scanner both need, and nothing that only one backend can
#: supply: no owner, mode or inode, because SMB over a userspace client cannot
#: answer those the way a local stat can, and a field that is only sometimes
#: populated invites callers to depend on it.
Entry = collections.namedtuple('Entry', 'name is_dir size mtime')


class Source(object):
    """A read-only tree of files reachable from the Hub."""

    #: Set by subclasses; used in error messages and the features endpoint.
    source_type = ''

    def list_dir(self, root_path, rel_path):
        """Entries directly under `rel_path`. Raises SourceNotFound.

        Returns entries in no particular order -- ordering is presentation, and
        a backend that has to sort a 100k-entry directory pays for it on every
        request whether the caller wanted that order or not.
        """
        raise NotImplementedError

    def stat(self, root_path, rel_path):
        """The Entry for `rel_path` itself. Raises SourceNotFound."""
        raise NotImplementedError

    def open_file(self, root_path, rel_path):
        """A context manager yielding a readable binary file object.

        A context manager rather than a bare handle because the download view
        streams the body: the file has to stay open past the point where the
        view returns, and closing it is the response's job.
        """
        raise NotImplementedError
