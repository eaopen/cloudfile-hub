# Organization depth contract — pure algorithm, not live permission changes

Development slice for [Hub #55](https://github.com/eaopen/cloudfile-hub/issues/55).

CloudFile maintains **flat native CE Groups**. A trusted Directory provides
an Org catalog with `parent_external_id`; this does not automatically create
CE parent/child groups, rewrite ACLs or grant permissions.

`org_parent_map(catalog_groups)` validates the complete Org parent graph
without a database: each Org has one parent at most, parent belongs to the
same provider/namespace, all non-root parents exist, and no cycle is allowed.
The Etech upstream adapter already sends only active-chain Org entities
with `parent_external_id`. Use this helper **after** trusted snapshot
freshness / entity validation (#54 / Draft #73); this helper is not another
HTTP authenticator.

`scoped_memberships(direct, parents, org_level=1)` computes a **candidate**
set of flat org memberships. A user's direct role memberships are unchanged:

| orgLevel | Candidate Org groups |
|---|---|
| 1 (default) | Direct Org only |
| 2 | Direct Org + one parent |
| N >= 2 | Direct Org and up to N-1 parents |
| 0 | Direct Org and all ancestors |

**Important: the returned set must not be written into CE GroupUser for a
rule-specific depth**. Such a global projection would grant additional
unrelated library/dir ACLs. Only a single consciously configured,
provider-wide depth can safely use a shared GroupUser projection; per-rule
depth needs a separate reviewed execution contract. Current Etech default
remains direct member (`orgLevel=1`) *once* #63 is separately approved.

This PR **does not** change existing `validate_subject`, ready markers,
`Memberships.ensure`, CE users, native groups, ACLs or cache. It is a
standalone verified algorithm with five-level / multi-membership / malformed
parent-graph unit tests. Integration requires coherent snapshots from #54,
#63 rollout compatibility check, and Etech DEV evidence before any effective
permission changes.

No new tables, background refresh, migration, network path or recursive
database query.
