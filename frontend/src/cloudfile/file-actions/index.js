import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Button, Spinner } from 'reactstrap';
import { gettext } from '../../utils/constants';
import toaster from '../../components/toast';
import { cloudFileAPI } from '../cloudfile-api';

import './index.css';

const query = new URLSearchParams(window.location.search);
const repoID = query.get('repo_id') || '';
const filePath = query.get('path') || '';

function errorMessage(error) {
  return error && error.response && error.response.data && error.response.data.detail
    ? error.response.data.detail
    : gettext('Unable to prepare this file action.');
}

function ActionCard({ action, onOpen, busy }) {
  return (
    <article className={`cf-action-card ${action.available ? '' : 'is-disabled'}`}>
      <div className="cf-action-card__topline">
        <span className={`cf-action-card__signal ${action.writes ? 'is-write' : 'is-read'}`}></span>
        <small>{action.writes ? gettext('WRITE WORKFLOW') : gettext('READ WORKFLOW')}</small>
      </div>
      <h2>{gettext(action.label)}</h2>
      <p>{gettext(action.description)}</p>
      {action.available ? (
        <Button color="primary" onClick={() => onOpen(action)} disabled={busy}>
          {busy ? <Spinner size="sm" /> : gettext('Open')}
        </Button>
      ) : (
        <div className="cf-action-card__blocked">{gettext('Unavailable: ')}{action.reason}</div>
      )}
    </article>
  );
}

function downloadSessionManifest(session) {
  const payload = JSON.stringify({
    protocol: session.protocol,
    server: window.location.origin,
    ticket: session.ticket,
    expires_at: session.expires_at,
  }, null, 2);
  const blob = new Blob([payload], { type: 'application/vnd.cloudfile.local-session+json' });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${session.file.name}.cloudfile`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

function LocalSession({ session, onDismiss }) {
  const isEdit = session.mode === 'local-edit';
  return (
    <section className="cf-agent-ticket" aria-live="polite">
      <div>
        <span className="cf-eyebrow">{gettext('LOCAL SOFTWARE SESSION')}</span>
        <h2>{isEdit ? gettext('Editing session ready') : gettext('Viewing session ready')}</h2>
        <p>{gettext('Download the short-lived .cloudfile session file. The portable and installed CloudFile Local agent use this same file to open your selected professional application.')}</p>
        <dl className="cf-agent-ticket__facts">
          <div><dt>{gettext('Mode')}</dt><dd>{isEdit ? gettext('Edit with protected write-back') : gettext('Read-only')}</dd></div>
          <div><dt>{gettext('Expires')}</dt><dd>{gettext('In ')}{session.expires_in}{gettext(' seconds')}</dd></div>
        </dl>
      </div>
      <div className="cf-agent-ticket__actions">
        <Button color="primary" onClick={() => downloadSessionManifest(session)}>{gettext('Download local session')}</Button>
        <Button outline color="secondary" onClick={onDismiss}>{gettext('Close')}</Button>
      </div>
    </section>
  );
}

function FileActions() {
  const [state, setState] = useState({ loading: true, actions: [], error: '' });
  const [busy, setBusy] = useState(false);
  const [session, setSession] = useState(null);
  const [checkout, setCheckout] = useState(null);
  const fileName = useMemo(() => filePath.split('/').filter(Boolean).pop() || gettext('File'), []);

  useEffect(() => {
    if (!repoID || !filePath) {
      setState({ loading: false, actions: [], error: gettext('A library ID and file path are required.') });
      return;
    }
    cloudFileAPI.getFileActions(repoID, filePath).then((res) => {
      setState({ loading: false, actions: res.data.actions || [], error: '' });
    }).catch((error) => setState({ loading: false, actions: [], error: errorMessage(error) }));
  }, []);

  const openAction = (action) => {
    if (action.id === 'native-preview' && action.url) {
      window.open(action.url, '_blank', 'noopener,noreferrer');
      return;
    }
    if (action.id === 'local-view') {
      setBusy(true);
      cloudFileAPI.createLocalSession(repoID, filePath).then((res) => {
        setSession(res.data);
      }).catch((error) => toaster.danger(errorMessage(error))).finally(() => setBusy(false));
      return;
    }
    if (action.id === 'local-edit') {
      setBusy(true);
      cloudFileAPI.createLocalSession(repoID, filePath, 'local-edit').then((res) => {
        setSession(res.data);
      }).catch((error) => toaster.danger(errorMessage(error))).finally(() => setBusy(false));
      return;
    }
    if (action.id === 'checkout') {
      setBusy(true);
      cloudFileAPI.checkoutFile(repoID, filePath, 'manual').then((res) => {
        setCheckout(res.data);
        toaster.success(gettext('File checked out.'));
      }).catch((error) => toaster.danger(errorMessage(error))).finally(() => setBusy(false));
    }
  };

  const releaseCheckout = () => {
    if (!checkout) return;
    setBusy(true);
    cloudFileAPI.releaseCheckout(repoID, filePath, checkout.generation).then(() => {
      setCheckout(null);
      toaster.success(gettext('File checked in.'));
    }).catch((error) => toaster.danger(errorMessage(error))).finally(() => setBusy(false));
  };

  return (
    <main className="cf-action-shell">
      <header className="cf-action-hero">
        <span className="cf-eyebrow">CLOUDFILE / OPEN WITH</span>
        <h1>{fileName}</h1>
        <p>{filePath || gettext('Choose a file workflow')}</p>
      </header>
      {state.loading && <div className="cf-loading"><Spinner /> {gettext('Reading available actions…')}</div>}
      {state.error && <div className="cf-error">{state.error}</div>}
      {!state.loading && !state.error && (
        <section className="cf-action-grid">
          {state.actions.length ? state.actions.map((action) => (
            <ActionCard key={action.id} action={action} onOpen={openAction} busy={busy} />
          )) : <p className="cf-empty">{gettext('No CloudFile action is available for this file.')}</p>}
        </section>
      )}
      {session && <LocalSession session={session} onDismiss={() => setSession(null)} />}
      {checkout && (
        <section className="cf-checkout-status" aria-live="polite">
          <div>
            <span className="cf-eyebrow">{gettext('MANUAL CHECKOUT ACTIVE')}</span>
            <h2>{gettext('This file is checked out by you')}</h2>
            <p>{gettext('Other writers are blocked until you check in or the lease expires.')}</p>
          </div>
          <Button color="primary" onClick={releaseCheckout} disabled={busy}>
            {busy ? <Spinner size="sm" /> : gettext('Check in')}
          </Button>
        </section>
      )}
    </main>
  );
}

createRoot(document.getElementById('wrapper')).render(<FileActions />);
