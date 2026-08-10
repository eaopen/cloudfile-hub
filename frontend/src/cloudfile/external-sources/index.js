import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Button, Input, Spinner } from 'reactstrap';
import { gettext } from '../../utils/constants';
import toaster from '../../components/toast';
import { cloudFileAPI } from '../cloudfile-api';
import { loadFeatures } from '../features';

import './index.css';

const rootCrumb = { name: gettext('Root'), path: '/' };

function errorMessage(error, fallback) {
  const data = error && error.response && error.response.data;
  return (data && (data.detail || data.error)) || fallback;
}

function breadcrumbs(path) {
  const parts = path.split('/').filter(Boolean);
  const crumbs = [rootCrumb];
  let current = '';
  parts.forEach((part) => {
    current += '/' + part;
    crumbs.push({ name: part, path: current });
  });
  return crumbs;
}

function formatSize(size) {
  if (size === null || size === undefined) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = Number(size);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function formatTime(timestamp) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString() : '—';
}

function parentPath(path) {
  const parts = (path || '/').split('/').filter(Boolean);
  parts.pop();
  return parts.length ? `/${parts.join('/')}` : '/';
}

function ExternalSearch({ sources, onOpenResult }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const search = (event) => {
    event.preventDefault();
    const value = query.trim();
    if (!value) return;
    setLoading(true);
    setMessage('');
    cloudFileAPI.searchExternalSources(value).then((res) => {
      setResults(res.data.results || []);
      if ((res.data.results || []).length === 0) setMessage(gettext('No indexed external files match this search.'));
    }).catch((error) => {
      setResults([]);
      setMessage(errorMessage(error, gettext('External search is unavailable.')));
    }).finally(() => setLoading(false));
  };

  return (
    <section className="cf-external-search" aria-label={gettext('Search external sources')}>
      <form onSubmit={search}>
        <label htmlFor="cf-external-search">{gettext('Indexed external files')}</label>
        <div>
          <Input id="cf-external-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={gettext('Search file names')} />
          <Button color="secondary" type="submit" disabled={loading}>{loading ? <Spinner size="sm" /> : gettext('Search')}</Button>
        </div>
      </form>
      {message && <p className="cf-external-muted">{message}</p>}
      {results.length > 0 && (
        <ol className="cf-external-search-results">
          {results.map((result) => {
            const source = sources.find((item) => item.id === result.source_id);
            return <li key={`${result.repo_id}:${result.path}`}><button type="button" onClick={() => source && onOpenResult(source, parentPath(result.path))}><strong>{result.name}</strong><span>{result.source_name} · {result.path}</span></button></li>;
          })}
        </ol>
      )}
    </section>
  );
}

function SourceBrowser({ sources, activeSource, listing, onSelectSource, onOpenPath, loading }) {
  const entries = listing && listing.dirent_list ? listing.dirent_list : [];
  const path = listing && listing.path ? listing.path : '/';

  return (
    <section className="cf-external-browser">
      <aside className="cf-external-sources" aria-label={gettext('External sources')}>
        <div className="cf-external-panel-heading">
          <span>{gettext('Sources')}</span><small>{sources.length}</small>
        </div>
        {sources.length === 0 && <p className="cf-external-muted">{gettext('No external source has been shared with you.')}</p>}
        {sources.map((source) => (
          <button type="button" key={source.id}
            className={`cf-external-source ${activeSource && activeSource.id === source.id ? 'is-active' : ''}`}
            onClick={() => onSelectSource(source)}>
            <span className="cf-external-source__marker"></span>
            <span><strong>{source.name}</strong><small>{source.source_type}</small></span>
          </button>
        ))}
      </aside>

      <div className="cf-external-listing">
        {!activeSource && <p className="cf-external-empty">{gettext('Choose a source to browse its shared files.')}</p>}
        {activeSource && (
          <>
            <div className="cf-external-pathbar">
              <div className="cf-external-crumbs">
                {breadcrumbs(path).map((crumb, index) => (
                  <React.Fragment key={crumb.path}>
                    {index > 0 && <span aria-hidden="true">/</span>}
                    <button type="button" onClick={() => onOpenPath(crumb.path)}>{crumb.name}</button>
                  </React.Fragment>
                ))}
              </div>
              <span className="cf-external-readonly">{gettext('READ ONLY')}</span>
            </div>
            {loading && <p className="cf-external-loading"><Spinner size="sm" /> {gettext('Reading source…')}</p>}
            {!loading && entries.length === 0 && <p className="cf-external-empty">{gettext('This directory is empty.')}</p>}
            {!loading && entries.length > 0 && (
              <div className="cf-external-table-wrap">
                <table className="cf-external-table">
                  <thead><tr><th>{gettext('Name')}</th><th>{gettext('Size')}</th><th>{gettext('Modified')}</th><th></th></tr></thead>
                  <tbody>{entries.map((entry) => (
                    <tr key={entry.path}>
                      <td>{entry.type === 'dir' ? <button type="button" className="cf-external-entry" onClick={() => onOpenPath(entry.path)}><span>□</span>{entry.name}</button> : <span className="cf-external-entry"><span>—</span>{entry.name}</span>}</td>
                      <td>{entry.type === 'dir' ? '—' : formatSize(entry.size)}</td>
                      <td>{formatTime(entry.mtime)}</td>
                      <td>{entry.type === 'file' && <a className="cf-external-download" href={cloudFileAPI.externalSourceDownloadUrl(activeSource.id, entry.path)}>{gettext('Download')}</a>}</td>
                    </tr>
                  ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}

function GrantEditor({ source }) {
  const [grants, setGrants] = useState([]);
  const [subject, setSubject] = useState('');
  const [subjectType, setSubjectType] = useState('user');
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(() => {
    if (!source) return;
    setLoading(true);
    cloudFileAPI.listExternalSourceGrants(source.id).then((res) => setGrants(res.data.grants || []))
      .catch((error) => toaster.danger(errorMessage(error, gettext('Unable to load access grants.'))))
      .finally(() => setLoading(false));
  }, [source]);

  useEffect(() => refresh(), [refresh]);
  if (!source) return null;

  const add = (event) => {
    event.preventDefault();
    if (!subject.trim()) return;
    cloudFileAPI.grantExternalSource(source.id, { subject_type: subjectType, subject: subject.trim(), permission: 'r' })
      .then(() => { setSubject(''); refresh(); toaster.success(gettext('Read access granted.')); })
      .catch((error) => toaster.danger(errorMessage(error, gettext('Unable to grant access.'))));
  };
  const revoke = (grant) => {
    cloudFileAPI.revokeExternalSourceGrant(source.id, grant.subject_type, grant.subject)
      .then(refresh).catch((error) => toaster.danger(errorMessage(error, gettext('Unable to revoke access.'))));
  };

  return (
    <section className="cf-external-grants">
      <div className="cf-external-section-title"><span>{gettext('Access grants')}</span><small>{source.name}</small></div>
      <form className="cf-external-grant-form" onSubmit={add}>
        <Input type="select" value={subjectType} onChange={(event) => setSubjectType(event.target.value)}><option value="user">{gettext('User')}</option><option value="group">{gettext('Group')}</option></Input>
        <Input value={subject} onChange={(event) => setSubject(event.target.value)} placeholder={gettext('User email or group name')} />
        <Button color="secondary" type="submit">{gettext('Grant read')}</Button>
      </form>
      {loading ? <Spinner size="sm" /> : (
        <ul className="cf-external-grant-list">{grants.map((grant) => (
          <li key={`${grant.subject_type}:${grant.subject}`}><span><code>{grant.subject_type}</code> {grant.subject}</span><button type="button" onClick={() => revoke(grant)}>{gettext('Revoke')}</button></li>
        ))}
        </ul>
      )}
    </section>
  );
}

function AdminPanel({ sources, allowedRoots, onRefresh }) {
  const [form, setForm] = useState({ name: '', root_path: '', source_type: 'local-path' });
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);

  const create = (event) => {
    event.preventDefault();
    setBusy(true);
    cloudFileAPI.createExternalSource(form).then(() => {
      setForm({ name: '', root_path: '', source_type: 'local-path' });
      toaster.success(gettext('External source registered.'));
      return onRefresh();
    }).catch((error) => toaster.danger(errorMessage(error, gettext('Unable to register external source.'))))
      .finally(() => setBusy(false));
  };
  const toggle = (source) => {
    cloudFileAPI.updateExternalSource(source.id, { enabled: !source.enabled }).then(onRefresh)
      .catch((error) => toaster.danger(errorMessage(error, gettext('Unable to update external source.'))));
  };
  const remove = (source) => {
    if (!window.confirm(gettext('Remove this external source and all of its grants?'))) return;
    cloudFileAPI.deleteExternalSource(source.id).then(() => {
      if (selected && selected.id === source.id) setSelected(null);
      return onRefresh();
    }).catch((error) => toaster.danger(errorMessage(error, gettext('Unable to remove external source.'))));
  };

  return (
    <section className="cf-external-admin">
      <div className="cf-external-section-title"><span>{gettext('Source administration')}</span><small>{gettext('System administrator')}</small></div>
      <p className="cf-external-muted">{gettext('Register directories already mounted in this container. Allowed roots: ')}{allowedRoots.join(', ') || '—'}</p>
      <form className="cf-external-create" onSubmit={create}>
        <Input required value={form.name} placeholder={gettext('Source name')} onChange={(event) => setForm({ ...form, name: event.target.value })} />
        <Input required value={form.root_path} placeholder="/shared/external/finance" onChange={(event) => setForm({ ...form, root_path: event.target.value })} />
        <Button color="primary" type="submit" disabled={busy}>{busy ? <Spinner size="sm" /> : gettext('Register')}</Button>
      </form>
      <div className="cf-external-admin-list">{sources.map((source) => (
        <div className="cf-external-admin-row" key={source.id}>
          <div><strong>{source.name}</strong><code>{source.root_path}</code></div>
          <span className={source.enabled ? 'cf-external-state is-on' : 'cf-external-state'}>{source.enabled ? gettext('Active') : gettext('Disabled')}</span>
          <Button size="sm" outline color="secondary" onClick={() => toggle(source)}>{source.enabled ? gettext('Disable') : gettext('Enable')}</Button>
          <Button size="sm" outline color="secondary" onClick={() => setSelected(source)}>{gettext('Access')}</Button>
          <Button size="sm" outline color="danger" onClick={() => remove(source)}>{gettext('Remove')}</Button>
        </div>
      ))}
      </div>
      <GrantEditor source={selected} />
    </section>
  );
}

function ExternalSources() {
  const [state, setState] = useState({ loading: true, sources: [], active: null, listing: null, error: '', admin: null });
  const [listingLoading, setListingLoading] = useState(false);

  const loadAdmin = useCallback(() => cloudFileAPI.listAdminExternalSources().then((res) => res.data).catch(() => null), []);
  const loadSources = useCallback(async () => {
    const [sourceResponse, admin] = await Promise.all([cloudFileAPI.listExternalSources(), loadAdmin()]);
    const sources = sourceResponse.data.sources || [];
    setState((old) => ({ ...old, loading: false, sources, admin, error: '' }));
    return { sources, admin };
  }, [loadAdmin]);
  const openPath = useCallback((source, path) => {
    if (!source) return;
    setListingLoading(true);
    cloudFileAPI.listExternalSourceDir(source.id, path).then((res) => {
      setState((old) => ({ ...old, active: source, listing: res.data, error: '' }));
    }).catch((error) => setState((old) => ({ ...old, error: errorMessage(error, gettext('Unable to read this source.')) })))
      .finally(() => setListingLoading(false));
  }, []);

  useEffect(() => {
    loadFeatures().then((features) => {
      if (!features.CF_ENABLE_EXTERNAL_SOURCES) {
        setState((old) => ({ ...old, loading: false, error: gettext('External sources are not enabled.') }));
        return;
      }
      loadSources().then(({ sources }) => { if (sources[0]) openPath(sources[0], '/'); })
        .catch((error) => setState((old) => ({ ...old, loading: false, error: errorMessage(error, gettext('Unable to load external sources.')) })));
    });
  }, [loadSources, openPath]);

  const refreshAdmin = () => loadSources().catch((error) => toaster.danger(errorMessage(error, gettext('Unable to refresh external sources.'))));
  return (
    <main className="cf-external-shell">
      <header className="cf-external-hero"><span className="cf-external-eyebrow">CLOUDFILE / EXTERNAL MOUNTS</span><h1>{gettext('External sources')}</h1><p>{gettext('Browse mounted SMB or NFS files without copying them into CloudFile storage.')}</p></header>
      <div className="cf-external-notice"><span>!</span>{gettext('External files are read-only here. Upload, sync, history, locking, and archive download are not available.')}</div>
      {state.loading && <p className="cf-external-loading"><Spinner /> {gettext('Loading external sources…')}</p>}
      {state.error && <p className="cf-external-error">{state.error}</p>}
      {!state.loading && !state.error && <ExternalSearch sources={state.sources} onOpenResult={openPath} />}
      {!state.loading && !state.error && <SourceBrowser sources={state.sources} activeSource={state.active} listing={state.listing} loading={listingLoading} onSelectSource={(source) => openPath(source, '/')} onOpenPath={(path) => openPath(state.active, path)} />}
      {state.admin && <AdminPanel sources={state.admin.sources || []} allowedRoots={state.admin.allowed_roots || []} onRefresh={refreshAdmin} />}
    </main>
  );
}

createRoot(document.getElementById('wrapper')).render(<ExternalSources />);
