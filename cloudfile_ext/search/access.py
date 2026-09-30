"""Request-local conservative search authority; no Django or native imports."""
import hashlib
import json
import time

from cloudfile_ext.acl import resolver
from cloudfile_extensions.resources.paths import normalize_path
from .bounded import SearchFailure


def unavailable():
    return SearchFailure('SEARCH_CHANGED', 'Search permissions unavailable or changed')


def canonical_snapshot(value):
    """Canonicalize trusted fresh reads, never HTTP-supplied policy data."""
    try:
        if set(value) != {'rules', 'subjects', 'native_rules', 'native_subjects', 'native_paths', 'state'}:
            raise ValueError()
        rules, subjects, paths = value['rules'], value['subjects'], value['native_paths']
        if (len(rules) > 4096 or len(subjects) > 4096 or len(paths) > 4096 or
                len(value['native_rules']) > 4096 or len(value['native_subjects']) > 4096):
            raise ValueError()
        def normalize_rules(items):
            return sorted([normalize_rule(rule) for rule in items], key=lambda r: json.dumps(r, sort_keys=True))
        def normalize_rule(rule):
            if (set(rule) != {'path', 'subject_type', 'subject', 'permission', 'inherit'} or
                    rule['subject_type'] not in resolver.SUBJECT_PRECEDENCE or
                    rule['permission'] not in resolver.PERMISSION_ORDER or
                    not isinstance(rule['subject'], str) or not rule['subject'] or
                    type(rule['inherit']) not in (int, bool) or rule['inherit'] not in (0, 1)):
                raise ValueError()
            return {**rule, 'path': checked_path(rule['path']), 'inherit': bool(rule['inherit'])}
        subjects = sorted(set(tuple(subject) for subject in subjects))
        if any(len(s) != 2 or s[0] not in resolver.SUBJECT_PRECEDENCE or
                not isinstance(s[1], str) or not s[1] for s in subjects):
            raise ValueError()
        native_subjects = sorted(set(tuple(s) for s in value['native_subjects']))
        if any(len(s) != 2 or s[0] not in ('user', 'group') or
                not isinstance(s[1], str) or not s[1] for s in native_subjects):
            raise ValueError()
        paths = sorted(set(checked_path(path) for path in paths))
        # State includes native account, membership, folder rules, eligibility
        # and status. A change rejects the page/cursor, even when it grants more.
        result = dict(rules=normalize_rules(rules), subjects=subjects,
            native_rules=normalize_rules(value['native_rules']), native_subjects=native_subjects,
            native_paths=paths, state=value['state'])
        # Detach mutable reader state; a reused dictionary must not mutate the
        # captured baseline and make a later policy change compare equal.
        return json.loads(json.dumps(result, allow_nan=False, ensure_ascii=False))
    except Exception:
        raise unavailable() from None


def checked_path(path):
    path = normalize_path(path, 'dir')
    if len(path.encode('utf-8')) > 4096 or len(path.split('/')) > 130:
        raise ValueError()
    return path


class SearchAccess:
    def __init__(self, snapshot_reader, native_permission, *, native_many=None, clock=time.monotonic):
        self.reader, self.native_permission, self.clock = snapshot_reader, native_permission, clock
        # Optional seam preserves existing scalar callers. Production legacy
        # Search supplies a strict batch transport; neither pass shares results.
        self.native_many = native_many
        self.native_inputs = {}
        self.deadline = clock() + 10
        self.snapshot = self._snapshot()
        self.version = hashlib.sha256(json.dumps(self.snapshot, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        self.subjects = set(map(tuple, self.snapshot['subjects']))
        self.native_subjects = set(map(tuple, self.snapshot['native_subjects']))
        self.rules_by_path = {}
        self.native_rules_by_path = {}
        for rule in self.snapshot['rules']:
            self.rules_by_path.setdefault(rule['path'], []).append(rule)
        for rule in self.snapshot['native_rules']:
            self.native_rules_by_path.setdefault(rule['path'], []).append(rule)
        self.boundaries = set(self.rules_by_path) | set(self.native_rules_by_path) | set(self.snapshot['native_paths']) | {'/'}
        self.decisions = {}

    def _budget(self):
        if self.clock() >= self.deadline:
            raise unavailable()

    def _snapshot(self):
        self._budget()
        try:
            return canonical_snapshot(self.reader())
        except Exception:
            raise unavailable() from None

    def _native(self, path):
        self._budget()
        try:
            permission = self.native_permission(path)
        except Exception:
            raise unavailable() from None
        # Never use truthiness: 'none', 'invisible', custom permissions and
        # readonly-library defaults are not native read qualification.
        self._budget()
        return permission if permission in ('r', 'rw') else None

    def _read_many(self, paths):
        self._budget()
        try:
            values = self.native_many(paths)
            if not isinstance(values, list) or len(values) != len(paths) or any(
                    value not in (None, 'r', 'rw') for value in values):
                raise ValueError()
        except Exception:
            raise unavailable() from None
        self._budget()
        return values

    def prepare_many(self, targets):
        """Load unique exact paths and configured ancestors, never parent grants.

        These inputs live only in the first pass. Object decisions still apply
        native folder rules and sparse ACL independently for every target.
        """
        if self.native_many is None:
            return
        paths = {}
        for target in targets:
            target = checked_path(target)
            boundaries = [ancestor for ancestor in resolver.ancestors(target)
                          if ancestor in self.boundaries]
            for path in [*boundaries, target]:
                if path not in self.native_inputs:
                    paths[path] = None
        if paths:
            self.native_inputs.update(zip(paths, self._read_many(list(paths))))

    def _decision(self, path):
        if path not in self.decisions:
            candidates = [rule for ancestor in resolver.ancestors(path)
                for rule in self.rules_by_path.get(ancestor, ())]
            native = self.native_inputs[path] if self.native_many is not None else self._native(path)
            native_rules = [rule for ancestor in resolver.ancestors(path)
                for rule in self.native_rules_by_path.get(ancestor, ())]
            # CE installations may not enforce Pro folder records in every
            # RPC. Fresh folder rules are a separate narrowing boundary, and
            # CF grants cannot override this native qualification boundary.
            native = resolver.resolve(native_rules, self.native_subjects, path, native)
            # This intersection can only narrow current native permission;
            # fresh sparse rules never manufacture native eligibility.
            self.decisions[path] = native is not None and resolver.resolve(
                candidates, self.subjects, path, native) in ('r', 'rw')
        return self.decisions[path]

    def __call__(self, target):
        self._budget()
        target = checked_path(target)
        self.prepare_many([target])
        for ancestor in resolver.ancestors(target):
            # Inspect configured boundaries, not every unconfigured directory.
            # A hidden ancestor must not leak through a deeper readable grant.
            if ancestor in self.boundaries and not self._decision(ancestor):
                return False
        return self._decision(target)

    def assert_current(self):
        if self._snapshot() != self.snapshot:
            raise unavailable()
        # Request-local reuse is never a response-time authority. Revalidate
        # every accepted path once; rejected paths cannot become new results.
        # 4A's OIDC provider/user/repo guards do not cover this native-token
        # identity and every legacy ACL/hook writer. Keep this pass until an
        # equivalent producer-coordinated scope can prove the same boundary.
        paths = [path for path, allowed in self.decisions.items() if allowed]
        # The second transport is deliberately independent of native_inputs:
        # it executes the scalar engine and Hub hooks again for every path.
        values = self._read_many(paths) if self.native_many is not None else [self._native(p) for p in paths]
        if any(value is None for value in values):
            raise unavailable()
        if self._snapshot() != self.snapshot:
            raise unavailable()
        self._budget()
