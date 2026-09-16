import { gettext, siteRoot } from '../utils/constants';
import toaster from '../components/toast';
import { cloudFileAPI } from './cloudfile-api';

const EXTENSION_ID = 'nafehcgbhfodbocmoghcigmfgjneogom';

function errorMessage(error) {
  const data = error && error.response && error.response.data;
  if (data && data.error_msg) return data.error_msg;
  if (data && data.detail) return data.detail;
  return gettext('Unable to prepare this file action.');
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
    if (runtime.lastError) {
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

// 创建一次性会话凭证 → 立即交给扩展 → 本地 Agent 打开。不弹页面、不下载文件。
export const openLocalSession = (repoID, filePath, mode = 'local-view') => {
  cloudFileAPI.createLocalSession(repoID, filePath, mode).then((res) => {
    openViaExtension(res.data);
  }).catch((error) => toaster.danger(errorMessage(error)));
};
