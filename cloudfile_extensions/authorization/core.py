"""Typed adapter to the same installed C policy core; no Python ACL solver."""
import ctypes as c
import json
import os

from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.protocol import validate_subject
from ..resources.paths import resource_ref
from .rules import rule_value


class Rule(c.Structure):
    _fields_ = [("path", c.c_char_p), ("subject_id", c.c_char_p),
                ("subject_type", c.c_int), ("permission", c.c_int),
                ("inherit", c.c_int), ("kind", c.c_int)]


class Context(c.Structure):
    _fields_ = [("user_id", c.c_char_p), ("departments", c.POINTER(c.c_char_p)),
                ("department_count", c.c_size_t), ("groups", c.POINTER(c.c_char_p)),
                ("group_count", c.c_size_t), ("ce_permission", c.c_int),
                ("ready", c.c_int), ("active", c.c_int),
                ("hard_readonly", c.c_int), ("barrier_active", c.c_int)]


class Result(c.Structure):
    _fields_ = [("visible", c.c_int), ("read", c.c_int), ("write", c.c_int)]


def identity(type_, provider, namespace, external):
    return json.dumps(dict(type=type_, provider=provider, namespace=namespace,
        external_id=external), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


class PolicyCore:
    def __init__(self, library_path):
        # Absolute deployment-controlled path, never accepted from an HTTP request.
        if not isinstance(library_path, str) or not os.path.isabs(library_path):
            raise ValueError("absolute trusted policy library required")
        try:
            self.library = c.CDLL(library_path)
            self.library.cf_acl_abi_version.argtypes = []
            self.library.cf_acl_abi_version.restype = c.c_int
            if self.library.cf_acl_abi_version() != 1:
                raise ValueError("unsupported policy ABI")
            self.evaluate_native = self.library.cf_acl_evaluate
            self.evaluate_native.argtypes = [c.POINTER(Context), c.c_char_p, c.c_int,
                c.POINTER(Rule), c.c_size_t, c.POINTER(Result)]
            self.evaluate_native.restype = c.c_int
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Native policy library is unavailable", 503) from None

    def evaluate(self, reference, *, provider, subject, rules, ce_permission,
                 attribute_allowlist=(), hard_readonly=False):
        ref = resource_ref(reference)
        identifier(provider, maximum=32)
        if (len(ref["path"].encode()) > 4096 or len(ref["path"].split("/")) > 130 or
                not isinstance(rules, list) or len(rules) > 4096 or
                (ce_permission is not None and (not isinstance(ce_permission, str) or ce_permission not in {"r", "rw"})) or
                type(hard_readonly) is not bool):
            raise ContractError("POLICY_UNAVAILABLE", "Policy input exceeds its contract", 503)
        subject = validate_subject(subject, requested_user_id=subject.get("userId"),
                                   attribute_allowlist=attribute_allowlist)
        deps = [identity("dept", provider, item["namespace"], item["external_id"])
                for item in subject["organizations"] + subject.get("organization_ancestors", [])]
        groups = [identity("group", provider, item["namespace"], item["external_id"]) for item in subject["roles"]]
        departments_array = (c.c_char_p * len(deps))(*deps)
        groups_array = (c.c_char_p * len(groups))(*groups)
        context = Context(identity("user", provider, "user", subject["userId"]),
            departments_array, len(deps), groups_array, len(groups),
            {None: 1, "r": 2, "rw": 3}[ce_permission], 1,
            int(subject["status"] == "active"), int(hard_readonly), 0)
        values = []
        for item in rules:
            value = rule_value({key: item[key] for key in ("path", "kind", "subject", "permission", "inherit")})
            s = value["subject"]
            values.append(Rule(value["path"].encode(), identity(s["type"], s["provider"], s["namespace"], s["external_id"]),
                {"user": 3, "dept": 2, "group": 1}[s["type"]],
                {"invisible": 0, "none": 1, "r": 2, "rw": 3}[value["permission"]],
                int(value["inherit"]), int(value["kind"] == "file")))
        array = (Rule * len(values))(*values)
        output = Result()
        if self.evaluate_native(c.byref(context), ref["path"].encode(), int(ref["kind"] == "file"),
                                array, len(values), c.byref(output)) != 0:
            raise ContractError("POLICY_UNAVAILABLE", "Native policy evaluation failed", 503)
        return dict(visible=bool(output.visible), read=bool(output.read), write=bool(output.write))
