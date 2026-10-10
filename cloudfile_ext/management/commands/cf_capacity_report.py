"""V05-01 bounded, read-only Seafile capacity snapshot.

No tree traversal, no writes, and no attempt to infer counts not maintained by CE.
"""
import json
import os
import re
import shutil
from datetime import datetime, timezone

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from seahub.utils.db_api import SeafileDB


def collect(*, db_name, limit, offset, disk_path=None, cursor_factory=None):
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", db_name or ""):
        raise ValueError("Seafile database name is unavailable/unsafe")
    if not 1 <= limit <= 1000 or not 0 <= offset <= 10000000:
        raise ValueError("limit/offset out of bounds")
    use_cursor = cursor_factory or connection.cursor
    result = {
        "schema": "cloudfile.capacity.v1",
        "build_version": os.environ.get("CF_BUILD_VERSION") or "unknown",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scope": "single_instance",
        "source": "Seafile CE Repo, RepoSize, RepoFileCount",
        "page": {"limit": limit, "offset": offset},
        "libraries": [],
        "metrics": {
            "directories": {"status": "unsupported"},
            "background_job_backlog": {"status": "unsupported"},
            "search_index_backlog": {"status": "unsupported"},
            "disk_available_bytes": {"status": "unknown"},
        },
        "errors": [],
    }
    # RepoFileCount includes files only; missing cached aggregate is unknown, not zero.
    sql = (
        f"SELECT r.repo_id, s.size, c.file_count FROM `{db_name}`.`Repo` r "
        f"LEFT JOIN `{db_name}`.`RepoSize` s ON r.repo_id=s.repo_id "
        f"LEFT JOIN `{db_name}`.`RepoFileCount` c ON r.repo_id=c.repo_id "
        "ORDER BY r.repo_id LIMIT %s OFFSET %s"
    )
    with use_cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM `{db_name}`.`Repo`")
        result["library_count"] = int(cursor.fetchone()[0])
        cursor.execute(sql, [limit, offset])
        for repo_id, size, count in cursor.fetchall():
            result["libraries"].append({
                "repo_id": str(repo_id),
                "logical_bytes": {"status": "ok", "value": int(size)} if size is not None
                    else {"status": "unknown"},
                "file_count": {"status": "ok", "value": int(count)} if count is not None
                    else {"status": "unknown"},
                "directory_count": {"status": "unsupported"},
            })
    result["page"]["has_more"] = offset + len(result["libraries"]) < result["library_count"]
    if disk_path:
        try:
            disk = shutil.disk_usage(disk_path)
            result["metrics"]["disk_available_bytes"] = {"status": "ok", "value": disk.free}
        except OSError:
            result["errors"].append("disk usage unavailable")
    return result


class Command(BaseCommand):
    help = "V05-01 read-only per-library capacity snapshot, no full-tree scans"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--offset", type=int, default=0)

    def handle(self, *args, **options):
        # The default is the trusted server data volume, not user-supplied paths.
        path = getattr(settings, "SEAFILE_DATA_DIR", None)
        try:
            report = collect(db_name=SeafileDB().db_name, limit=options["limit"],
                             offset=options["offset"], disk_path=path)
        except Exception as exc:
            # Do not leak DB credentials/SQL errors to an operator console.
            raise CommandError("read-only capacity query unavailable; check database/configuration") from exc
        self.stdout.write(json.dumps(report, ensure_ascii=False, sort_keys=True))
