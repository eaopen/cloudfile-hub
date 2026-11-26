"""Bounded permission-aware Meilisearch candidate paging, without SQL state.

Query validation, signed cursor binding, trusted scope filters, and current CE/ACL
permission checks are responsibilities of the integrating API adapter. The only
results returned here are freshly resolved authoritative objects, never raw hits.
"""


class SearchPageUnavailable(RuntimeError):
    pass


def page(*, limit, offset, fetch_candidates, resolve_authorized, query_budget=2):
    """Scan at most two candidate batches, but never insist on filling a page.

    fetch_candidates(offset, count) -> list of (repo_id,path,kind) references.
    resolve_authorized(references) -> same-length list of CURRENT CE objects or
    None. Its caller must apply trusted scope + effective V2 ACL and must not
    build successful objects from untrusted Meilisearch hit attributes.

    next_offset counts consumed candidates, not authorized results. Both batches
    prefetch one candidate to detect continuation without consuming that item.
    """
    if (type(limit) is not int or not 1 <= limit <= 100 or
            type(offset) is not int or offset < 0 or query_budget not in (1, 2) or
            not callable(fetch_candidates) or not callable(resolve_authorized)):
        raise ValueError("invalid page arguments")
    cursor, results, calls, exhausted = offset, [], 0, False
    min_acceptable = (limit + 4) // 5  # strictly fewer than 20% qualifies for one retry
    while calls < query_budget:
        # The extra candidate is only a lookahead, not part of the consumed page.
        candidates = fetch_candidates(cursor, limit + 1)
        calls += 1
        if not isinstance(candidates, list) or len(candidates) > limit + 1:
            raise SearchPageUnavailable("invalid candidate page")
        count = min(len(candidates), limit, limit - len(results))
        consumed = candidates[:count]
        for candidate in consumed:
            if (not isinstance(candidate, dict) or
                    not all(isinstance(candidate.get(k), str) and candidate[k]
                            for k in ("repo_id", "path", "kind")) or
                    candidate["kind"] not in ("file", "dir")):
                raise SearchPageUnavailable("invalid search reference")
        # A missing/unavailable authority fails the whole response, not just an item.
        resolved = resolve_authorized(consumed) if consumed else []
        if not isinstance(resolved, list) or len(resolved) != count:
            raise SearchPageUnavailable("incomplete authority decision")
        for candidate, current in zip(consumed, resolved):
            if current is None:
                continue
            if (not isinstance(current, dict) or
                    any(current.get(key) != candidate[key]
                        for key in ("repo_id", "path", "kind"))):
                raise SearchPageUnavailable("mismatched authority decision")
            results.append(dict(current))
        cursor += count
        exhausted = len(candidates) <= count
        if (exhausted or len(results) >= limit or calls >= query_budget or
                len(results) >= min_acceptable):
            break
    return dict(items=results, next_offset=None if exhausted else cursor,
                examined=cursor - offset, candidate_queries=calls)

def ranked_page(*, limit, offset, stage, number_query, fetch_candidates, resolve_authorized):
    """A signed (stage, offset) walks all literal hits before any typo matches."""
    def fetch(start, count):
        return fetch_candidates(stage, start, count)

    result = page(limit=limit, offset=offset, fetch_candidates=fetch, resolve_authorized=resolve_authorized)
    if number_query and stage == 'literal' and result['next_offset'] is None:
        stage = 'fuzzy'
        free = limit - len(result['items'])
        budget = 2 - result['candidate_queries']
        if free and budget:
            tail = page(limit=free, offset=0, fetch_candidates=fetch,
                        resolve_authorized=resolve_authorized, query_budget=budget)
            result['items'].extend(tail['items'])
            result['next_offset'] = tail['next_offset']
        else:
            result['next_offset'] = 0
    return result['items'], stage, result['next_offset']
