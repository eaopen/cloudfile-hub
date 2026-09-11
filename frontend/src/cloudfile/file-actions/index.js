import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Button, Spinner } from 'reactstrap';
import { gettext, siteRoot } from '../../utils/constants';
import toaster from '../../components/toast';
import { cloudFileAPI } from '../cloudfile-api';

import './index.css';

const query = new URLSearchParams(window.location.search);
const repoID = query.get('repo_id') || '';
const filePath = query.get('path') || '';

const EXTENSION_ID = 'nafehcgbhfodbocmoghcigmfgjneogom';

function errorMessage(error) {
  const data = error && error.response && error.response.data;
  if (data && data.error_msg) return data.error_msg;
  if (data && data.detail) return data.detail;
  return gettext('Unable to prepare this file action.');
}

// 后端 policy 返回的 reason 是机器可读标识，这里映射成可读中文提示。
function reasonText(reason) {
  const map = {
    file_lock_provider_required: gettext('本地编辑需要文件锁服务，请确认服务端锁提供者已就绪。'),
    edit_permission_required: gettext('当前账号没有编辑该文件的权限。'),
  };
  return map[reason] || gettext('该操作暂不可用。');
}

// 网页 → 扩展 → 本地 Agent 的消息通道。票据仍是一次性短命凭证，安全模型不变。
function openViaExtension(session) {
  const payload = {
    type: 'open_session',
    protocol: session.protocol,
    server: window.location.origin + siteRoot,
    ticket: session.ticket,
    expires_at: session.expires_at,
  };
  const runtime = window.chrome && window.chrome.runtime;
  if (!runtime || typeof runtime.sendMessage !== 'function') {
    toaster.danger(gettext('CloudFile 本地扩展未安装或未启用，请检查浏览器扩展。'));
    return;
  }
  runtime.sendMessage(EXTENSION_ID, payload, (response) => {
    if (chrome.runtime.lastError) {
      toaster.danger(gettext('CloudFile 本地扩展未响应，请确认扩展已启用。'));
      return;
    }
    if (response && response.ok) {
      toaster.success(gettext('已交给本地 Agent 打开。'));
    } else {
      toaster.danger(response && response.error ? response.error : gettext('本地 Agent 未能打开该文件。'));
    }
  });
}

function ActionButton({ id, title, description, available, reason, busy, onOpen }) {
  return (
    <article className={`cf-action-card ${available ? '' : 'is-disabled'}`}>
      <div className="cf-action-card__topline">
        <span className={`cf-action-card__signal ${id === 'local-edit' ? 'is-write' : 'is-read'}`}></span>
        <small>{id === 'local-edit' ? gettext('WRITE WORKFLOW') : gettext('READ WORKFLOW')}</small>
      </div>
      <h2>{title}</h2>
      <p>{description}</p>
      {available ? (
        <Button color="primary" onClick={() => onOpen(id)} disabled={busy}>
          {busy ? <Spinner size="sm" /> : title}
        </Button>
      ) : (
        <div className="cf-action-card__blocked">{gettext('Unavailable: ')}{reason}</div>
      )}
    </article>
  );
}

function FileActions() {
  const [state, setState] = useState({ loading: true, actions: [], error: '' });
  const [busy, setBusy] = useState(false);
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

  const actionFor = (id) => state.actions.find((a) => a.id === id);

  // 点击即走：创建会话 → 拿到凭证立即交给扩展 → agent 打开，无中间确认。
  const openLocal = (mode) => {
    setBusy(true);
    cloudFileAPI.createLocalSession(repoID, filePath, mode).then((res) => {
      openViaExtension(res.data);
    }).catch((error) => toaster.danger(errorMessage(error))).finally(() => setBusy(false));
  };

  const renderButton = (id, title, description) => {
    const action = actionFor(id);
    if (!action) return null;
    // 无编辑权限：本地编辑按钮直接隐藏，不给用户看到不可用的入口。
    if (id === 'local-edit' && !action.available && action.reason === 'edit_permission_required') {
      return null;
    }
    const available = action.available;
    const reason = reasonText(action.reason);
    return (
      <ActionButton
        id={id}
        title={title}
        description={description}
        available={available}
        reason={reason}
        busy={busy}
        onOpen={openLocal}
      />
    );
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
          {renderButton('local-view', gettext('本地打开'), gettext('使用本地软件以只读方式打开该文件。'))}
          {renderButton('local-edit', gettext('本地编辑'), gettext('使用本地软件编辑该文件，保存后自动写回。'))}
        </section>
      )}
    </main>
  );
}

createRoot(document.getElementById('wrapper')).render(<FileActions />);
