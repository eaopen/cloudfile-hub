"""Deployment-owned scan budgets; they are not reservations across workers."""
from dataclasses import dataclass, fields
import re


@dataclass(frozen=True)
class ScanLimits:
    maximum_entries: int = 1000000
    maximum_report_bytes: int = 256 * 1024 * 1024
    maximum_seconds: int = 3600
    minimum_free_bytes: int = 64 * 1024 * 1024
    maximum_depth: int = 128

    def __post_init__(self):
        ceilings = (100000000, 16 * 1024 ** 3, 86400, 1024 ** 4, 256)
        for item, ceiling in zip(fields(self), ceilings):
            value = getattr(self, item.name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("invalid import scan budget: " + item.name)

    @classmethod
    def from_environment(cls, environment):
        values = {}
        for item in fields(cls):
            key = "CLOUDFILE_IMPORT_SCAN_" + item.name.upper()
            if key in environment:
                raw = environment[key]
                if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,16}", raw):
                    raise ValueError("invalid import scan budget: " + item.name)
                values[item.name] = int(raw)
        return cls(**values)
