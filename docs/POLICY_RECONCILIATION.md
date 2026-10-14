# Policy reconciliation without redundant mutations

The authorization rule store treats a replacement with the same normalized value
as a successful no-op. This avoids revision churn and misleading policy-change
audit events when external configuration managers reconcile periodically.

Authorization, management-scope checks, resource checks and strong `If-Match`
validation still run before comparing the value. A stale ETag is not accepted
merely because the requested value matches. The existing rule ID, revision and
ETag are returned. Durable idempotency results and transaction finalization are
preserved; actual changes and deletions retain their existing behavior.

No schema or API change is required. Clients should still compare remote rules
before sending a replacement, and should avoid contacting Hub at all when their
successfully applied desired state and subject membership have not changed.
An explicit repair operation should bypass the client's local fingerprint cache,
read the remote state and write only differences. Repair operations after deletion
must use fresh idempotency keys rather than replay a historical creation receipt.

Validation: `cloudfile_extensions/tests/test_acl_rules.py` exercises this behavior
with an isolated MariaDB instance, including unchanged revisions, audit counts,
durable replay and current authorization enforcement.
