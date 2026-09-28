import React, { useEffect, useState } from 'react';
import MainPanelTopbar from '@/components/admin/layout/main-panel-topbar';
import { gettext, siteRoot } from '@/utils/constants';

const CATEGORIES = [
  ['login', gettext('Login')],
  ['access', gettext('File Access')],
  ['updates', gettext('File Update')],
  ['permissions', gettext('Permission')],
];

const localDateTime = (date) => {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
};

const initialFilters = () => ({
  start: localDateTime(new Date(Date.now() - 7 * 86400000)),
  end: localDateTime(new Date()),
  repo_id: '',
  actor: '',
});

const CloudFileAuditLogs = (props) => {
  const [category, setCategory] = useState('login');
  const [draft, setDraft] = useState(initialFilters);
  const [filters, setFilters] = useState(initialFilters);
  const [cursor, setCursor] = useState(null);
  const [previous, setPrevious] = useState([]);
  const [nextCursor, setNextCursor] = useState(null);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      setLoading(true);
      setError('');
      try {
        const params = new URLSearchParams({
          start: new Date(filters.start).toISOString(),
          end: new Date(filters.end).toISOString(),
          limit: '100',
        });
        if (filters.actor) params.set('actor', filters.actor);
        if (filters.repo_id && category !== 'login') params.set('repo_id', filters.repo_id);
        if (cursor) params.set('cursor', cursor);
        const response = await fetch(`${siteRoot}api/v2.1/cloudfile/extensions/audit/v1/admin/${category}/?${params}`, {
          credentials: 'same-origin',
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(response.status === 403 ? gettext('Permission denied') : gettext('Failed to load audit logs'));
        const page = await response.json();
        setItems(page.items);
        setNextCursor(page.next_cursor);
      } catch (failure) {
        if (failure.name !== 'AbortError') {
          setItems([]);
          setNextCursor(null);
          setError(failure.message);
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    load();
    return () => controller.abort();
  }, [category, filters, cursor]);

  const selectCategory = (selected) => {
    setCategory(selected);
    setCursor(null);
    setPrevious([]);
  };

  const applyFilters = (event) => {
    event.preventDefault();
    const start = new Date(draft.start).getTime();
    const end = new Date(draft.end).getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 31 * 86400000) {
      setError(gettext('Choose a time range of up to 31 days'));
      return;
    }
    setCursor(null);
    setPrevious([]);
    setFilters({ ...draft });
  };

  const nextPage = () => {
    setPrevious([...previous, cursor]);
    setCursor(nextCursor);
  };

  const previousPage = () => {
    setCursor(previous[previous.length - 1]);
    setPrevious(previous.slice(0, -1));
  };

  return (
    <>
      <MainPanelTopbar {...props} />
      <div className="system-admin-logs h-100 w-100 overflow-auto p-4">
        <div className="d-flex gap-3 mb-4" role="tablist" aria-label={gettext('Logs')}>
          {CATEGORIES.map(([key, label]) => (
            <button key={key} type="button" role="tab" aria-selected={category === key}
              className={`btn ${category === key ? 'btn-primary' : 'btn-outline-secondary'}`}
              onClick={() => selectCategory(key)}>{label}
            </button>
          ))}
        </div>
        <form className="d-flex flex-wrap align-items-end gap-3 mb-4" onSubmit={applyFilters}>
          <label>{gettext('Start Time')}
            <input className="form-control" type="datetime-local" required value={draft.start}
              onChange={(event) => setDraft({ ...draft, start: event.target.value })} />
          </label>
          <label>{gettext('End Time')}
            <input className="form-control" type="datetime-local" required value={draft.end}
              onChange={(event) => setDraft({ ...draft, end: event.target.value })} />
          </label>
          <label>{gettext('User')}
            <input className="form-control" value={draft.actor}
              onChange={(event) => setDraft({ ...draft, actor: event.target.value })} />
          </label>
          {category !== 'login' && (
            <label>{gettext('Library ID')}
              <input className="form-control" value={draft.repo_id}
                onChange={(event) => setDraft({ ...draft, repo_id: event.target.value })} />
            </label>
          )}
          <button className="btn btn-primary" type="submit">{gettext('Search')}</button>
        </form>
        {error && <div className="alert alert-danger" role="alert">{error}</div>}
        {loading ? <div>{gettext('Loading...')}</div> : (
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>{gettext('Time')}</th><th>{gettext('User')}</th>
                  <th>{category === 'login' ? gettext('IP Address') : gettext('Library ID')}</th>
                  {category !== 'login' && <><th>{gettext('Operation')}</th><th>{gettext('Path')}</th><th>{gettext('IP Address')}</th></>}
                  <th>{gettext('Result')}</th>
                </tr>
              </thead>
              <tbody>{items.map((item) => (
                <tr key={item.id}>
                  <td>{new Date(item.occurred_at).toLocaleString()}</td>
                  <td>{item.actor || item.actor_user_id || item.operator}</td>
                  <td>{category === 'login' ? item.ip : item.repo_id}</td>
                  {category !== 'login' && <><td>{item.operation}</td><td>{item.source_path || item.target_path || '/'}</td><td>{item.client_ip || ''}</td></>}
                  <td>{item.result}</td>
                </tr>
              ))}
              </tbody>
            </table>
            {items.length === 0 && <div className="text-center p-4">{gettext('No logs')}</div>}
          </div>
        )}
        <div className="d-flex gap-2 mt-3">
          <button type="button" className="btn btn-outline-secondary" disabled={loading || !previous.length}
            onClick={previousPage}>{gettext('Previous')}
          </button>
          <button type="button" className="btn btn-outline-secondary" disabled={loading || !nextCursor}
            onClick={nextPage}>{gettext('Next')}
          </button>
        </div>
      </div>
    </>
  );
};

export default CloudFileAuditLogs;
