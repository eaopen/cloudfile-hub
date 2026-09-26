"""Complete bounded page manifest, including empty pages without remote tasks."""
import re
from .execution import step_hash


def fanout_pages_complete(sql, *, event_id, generation, index, batches, locking=False):
    if type(batches) is not int or not 0 <= batches <= 10001:
        return False
    sql.execute("SELECT p.batch,p.index_uid,p.payload_hash,p.empty_page,p.task_id,t.state,t.payload_hash,t.task_id FROM cf_search_fanout_page p LEFT JOIN cf_search_task t ON t.event_id=p.event_id AND t.index_generation=p.index_generation AND t.step=p.batch WHERE p.event_id=%s AND p.index_generation=%s ORDER BY p.batch LIMIT 10002" + (" FOR UPDATE" if locking else ""), (event_id, generation))
    rows = sql.fetchall()
    if len(rows) != batches:
        return False
    for position, row in enumerate(rows):
        if (len(row) != 8 or type(row[0]) is not int or row[0] != position or row[1] != index or
                not isinstance(row[2], str) or not re.fullmatch(r"[0-9a-f]{64}", row[2]) or
                type(row[3]) is not int or row[3] not in (0, 1)):
            return False
        if row[3] == 1:
            if row[2] != step_hash(index, "replace", b"[]") or any(value is not None for value in row[4:]):
                return False
        elif (type(row[4]) is not int or not 0 <= row[4] <= 2 ** 63 - 1 or row[5] != "succeeded" or
                row[6] != row[2] or type(row[7]) is not int or row[7] != row[4]):
            return False
    return True
