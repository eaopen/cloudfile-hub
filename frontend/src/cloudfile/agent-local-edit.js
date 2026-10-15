// The ID is derived from the stable public key in
// cloudfile-chrome-extension/manifest.json, not from a privileged browser API.
// The extension still validates sender origin, paired device and session URI.
// Windows uses the SINGLE com.cloudfile.current_agent Native Host.
export const CLOUDFILE_EXTENSION_ID = 'gocnpbhnbikcpnlafmodflddgnmfcjoc';

const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function extensionRuntime() {
  return typeof window !== 'undefined' && window.chrome && window.chrome.runtime;
}

// One external message, one answer. The extension rejects any message whose
// origin is not the page's own, so this never authorizes a foreign instance.
function extensionMessage(message) {
  return new Promise((resolve, reject) => {
    const runtime = extensionRuntime();
    if (!runtime || typeof runtime.sendMessage !== 'function') {
      reject(new Error('未安装或未启用受信 Chrome 扩展'));
      return;
    }
    runtime.sendMessage(CLOUDFILE_EXTENSION_ID, message, response => {
      if (runtime.lastError || !response || response.ok !== true) {
        reject(new Error(response?.error || '本机 Agent 未确认配对步骤'));
      } else {
        resolve(response);
      }
    });
  });
}

function validServicePath(servicePath) {
  return typeof servicePath === 'string' && servicePath.length <= 100 &&
    (servicePath === '' || /^(\/[A-Za-z0-9_-]+)+$/.test(servicePath));
}

// The same cookie names the Hub itself uses; the page only ever hands its own
// session and CSRF token back to its own same-origin deployment.
function csrfToken() {
  const cookies = (typeof document !== 'undefined' && document.cookie
    ? document.cookie : '').split(';').map(value => value.trim());
  const cookie = cookies.find(value => value.startsWith('sfcsrftoken=')) ||
    cookies.find(value => value.startsWith('csrftoken='));
  if (cookie) return decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1));
  if (typeof document === 'undefined') return '';
  const input = document.querySelector('[name=csrfmiddlewaretoken]');
  return input ? input.value : '';
}

async function pairRequest(servicePath, operation, body) {
  if (!validServicePath(servicePath)) throw new Error('CloudFile 部署路径无效');
  const token = csrfToken();
  if (!token) throw new Error('请先在当前页面登录 CloudFile');
  const response = await fetch(window.location.origin + servicePath +
    '/api/v2.1/cloudfile/extensions/local-edit/v1/devices/' + operation + '/', {
    method: 'POST', credentials: 'same-origin', redirect: 'error',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': token },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    // 403 on status means the local key belongs to a different account: never
    // reuse that pairing silently.
    if (response.status === 403) throw new Error('本机设备属于其他账号或已被撤销，未复用原有配对');
    throw new Error('服务未确认设备配对（HTTP ' + response.status + '）');
  }
  return response.json();
}

// First "open locally / edit" click from an already authenticated page. The
// page keeps its own session and CSRF token; this only starts a device
// registration when this machine is not paired yet. Later opens reuse it, so
// the user only ever perceives "open the file".
export async function ensurePairedLocalAgent({ servicePath = '' } = {}) {
  const server = window.location.origin;
  const prepared = await extensionMessage({
    type: 'pair_prepare', server, service_path: servicePath,
  });
  if (prepared.state === 'paired') {
    if (!DEVICE_ID.test(prepared.device_id || ''))
      throw new Error('本机 Agent 返回的设备编号无效');
    // The server stays the authority: confirm this exact device still belongs
    // to the current business user before reusing it. OAuth and native OIDC
    // resolve to the same UID, so switching auth method does not re-pair.
    const status = await pairRequest(servicePath, 'status', { device_id: prepared.device_id });
    if (status.state !== 'active') throw new Error('本机设备连接已失效，请在 Agent 任务中心重新连接');
    return { device_id: prepared.device_id, paired: true };
  }
  const started = await pairRequest(servicePath, 'pair-start', prepared.enrollment);
  if (!DEVICE_ID.test(started.device_id || '')) throw new Error('服务未返回有效设备编号');
  const { proof } = await extensionMessage({
    type: 'pair_sign', server, response: started,
  });
  const confirmed = await pairRequest(servicePath, 'pair-confirm', proof);
  await extensionMessage({ type: 'pair_confirm', server, response: confirmed });
  if (!DEVICE_ID.test(confirmed.device_id || '')) throw new Error('服务未确认设备编号');
  return { device_id: confirmed.device_id, paired: false };
}

export function launchPairedAgent(openURI) {
  return new Promise((resolve, reject) => {
    const runtime = extensionRuntime();
    if (!(window.location.protocol === 'https:' ||
        window.location.protocol === 'http:') ||
        typeof openURI !== 'string' || openURI.length > 2048 ||
        !openURI.startsWith('cloudfile-open://v1/open?instance=') ||
        !runtime || typeof runtime.sendMessage !== 'function') {
      reject(new Error('CloudFile Agent 需要 HTTP/HTTPS CloudFile 实例 与受信 Chrome 扩展'));
      return;
    }
    try {
      const url = new URL(openURI);
      const instance = url.searchParams.get('instance');
      if (url.protocol !== 'cloudfile-open:' || url.hostname !== 'v1' ||
          url.pathname !== '/open' || instance !== window.location.origin)
        throw new Error('本地 Agent URI 与当前 CloudFile 实例不匹配');
      runtime.sendMessage(CLOUDFILE_EXTENSION_ID,
        { type: 'open_uri', uri: openURI }, response => {
          const failure = runtime.lastError;
          if (failure || !response || response.ok !== true) {
            // A previously accepted short-lived ticket is NEVER reissued
            // automatically. The original local session must be reconciled.
            reject(new Error('Agent 打开结果未确认；请检查本地窗口或原会话状态，不重复领取票据'));
          } else {
            resolve({ accepted: true });
          }
        });
    } catch {
      reject(new Error('无法连接受信 Chrome 插件，不会尝试其他 Host'));
    }
  });
}
