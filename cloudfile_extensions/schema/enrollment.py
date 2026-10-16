"""Legacy enrollment only; M1 uses current ACL rows and has no sticky marker."""


def enroll_library(cursor, repo_id):
    cursor.execute("SELECT COUNT(*) FROM cf_schema_migration WHERE version='100_m1_storage'")
    if cursor.fetchone() == (1,):
        return
    cursor.execute("INSERT INTO cf_managed_library(repo_id,created_at) VALUES(%s,UTC_TIMESTAMP(6)) "
                   "ON DUPLICATE KEY UPDATE repo_id=VALUES(repo_id)", (repo_id,))
