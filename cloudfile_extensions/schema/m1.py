"""Superseded unpublished M1 experiment; not the V2 schema baseline."""
from .runner import Migration, MigrationError, load_migrations

PROFILE_VERSION = "100_m1_storage"
TABLES = frozenset({
    "cf_schema_migration", "cf_library_storage_key", "cf_dir_acl",
    "cf_sso_group_map", "cf_background_job", "cf_event_outbox", "cf_audit_event",
    "cf_policy_request", "cf_oidc_session", "cf_oidc_logout_fence",
    "cf_library_share_revision", "cf_library_share_ledger",
})


def migrations():
    existing = {item.version: item for item in load_migrations()}
    # Reuse immutable contracts required by the current M1 runtime, including
    # native OIDC receipts. Optional Tag/Search/Agent/editing tables stay out.
    selected = ("002_jobs", "003_outbox", "004_audit", "005_audit_query",
                "006_group_maps", "007_group_map_contract", "010_policy_requests",
                "012_oidc_sessions", "013_oidc_logout_fences", "014_oidc_scope_expiry",
                "023_outbox_stream_sequence", "033_audit_admin_page",
                "034_audit_client_ip", "035_library_shares")
    storage = Migration(PROFILE_VERSION, ({
        "sql": "CREATE TABLE cf_library_storage_key (repo_key VARCHAR(80) NOT NULL PRIMARY KEY,repo_id CHAR(36) NOT NULL UNIQUE) ENGINE=InnoDB",
        "verify": "SELECT IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_library_storage_key' AND engine='InnoDB')=1 AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_library_storage_key')=2 AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_library_storage_key' AND ((column_name='repo_key' AND data_type='varchar' AND character_maximum_length=80 AND is_nullable='NO' AND column_key='PRI') OR (column_name='repo_id' AND data_type='char' AND character_maximum_length=36 AND column_key='UNI')))=2,1,0)",
        "expected": 1,
    },))
    base = existing["008_directory_acl"].steps[0]
    sql = base["sql"].replace(") ENGINE=InnoDB", ",share_mode TINYINT NOT NULL DEFAULT 0,"
        "lifecycle_ref VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',"
        "KEY acl_library_page(repo_id,id),KEY acl_shared_recipient(subject_hash,share_mode,repo_id,path_hash)) ENGINE=InnoDB")
    acl = Migration("102_m1_directory_acl", (
        {**base, "sql": sql},
        *({**step, "sql": "SELECT 1"} for step in existing["042_unified_directory_acl"].steps[:2]),
        {**existing["036_library_acl_page"].steps[0], "sql": "SELECT 1"},
    ))
    return (storage, *(existing[version] for version in selected), acl)


def preflight(runner):
    rows = runner._query("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()")
    names = {row[0] for row in rows if row[0].startswith("cf_")}
    recorded = runner.status()
    initialized = any(row["version"] == PROFILE_VERSION for row in recorded)
    if not initialized:
        # Existing CE data and storage reservations are allowed, but a running
        # legacy CloudFile database must never be silently converted or erased.
        if recorded or names - {"cf_library_storage_key", "cf_schema_migration"}:
            raise MigrationError("M1 requires a clean CloudFile configuration; no legacy conversion is provided")
    elif names - TABLES:
        raise MigrationError("M1 contains unsupported extension tables")


def require_layout(runner):
    rows = runner._query("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()")
    names = {row[0] for row in rows if row[0].startswith("cf_")}
    if names != TABLES:
        raise MigrationError("M1 table inventory has drifted")
