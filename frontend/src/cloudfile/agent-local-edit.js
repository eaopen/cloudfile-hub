// The ID is derived from the stable public key in
// cloudfile-chrome-extension/manifest.json, not from a privileged browser API.
// The extension still validates the sender origin and the one-time session URI.
// Windows uses the SINGLE com.cloudfile.current_agent Native Host.
export const CLOUDFILE_EXTENSION_ID = 'gocnpbhnbikcpnlafmodflddgnmfcjoc';

const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function extensionRuntime() {
  return typeof window !== 'undefined' && window.chrome && window.chrome.runtime;
}

// Stateless V2 handoff. The Chrome extension requires Agent2 and validates
// the sender origin; the Agent independently verifies its scoped JWT against
// the native V2 fileserver. No legacy device pairing or cf_edit_session.
export function launchPairedAgent(openURI) {
  return new Promise((resolve, reject) => {
    const runtime = extensionRuntime();
    if (typeof openURI !== 'string' || openURI.length > 16384 ||
        !openURI.startsWith('cloudfile-open://v2/open?') ||
        !runtime || typeof runtime.sendMessage !== 'function') {
      reject(new Error('需要 CloudFile Agent2 与受信 Chrome 扩展'));
      return;
    }
    try {
      const uri = new URL(openURI);
      const instance = uri.searchParams.get('instance');
      const session = uri.searchParams.get('session');
      const ticket = uri.searchParams.get('ticket');
      if (uri.protocol !== 'cloudfile-open:' || uri.hostname !== 'v2' ||
          uri.pathname !== '/open' || uri.hash ||
          [...uri.searchParams.keys()].join(',') !== 'instance,session,ticket' ||
          instance !== window.location.origin ||
          !DEVICE_ID.test(session || '') ||
          !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(ticket || '')) {
        throw new Error('invalid local edit intent');
      }
      runtime.sendMessage(CLOUDFILE_EXTENSION_ID,
        { type: 'open_uri', uri: openURI }, response => {
          if (runtime.lastError || !response || response.ok !== true) {
            reject(new Error(response?.error ||
              'Agent2 未确认打开结果；请检查任务中心，勿重复发布未知状态任务'));
          } else {
            resolve({ accepted: true });
          }
        });
    } catch {
      reject(new Error('本地编辑票据与当前 CloudFile 实例不匹配'));
    }
  });
}

// A click is a single V2 browser-authorized handoff; never create a legacy
// session or silently switch to an unscoped Seafile download token.
export async function openV2LocalFile({ repoID, path, mode = 'optimistic-edit' }) {
  const { cloudFileAPI } = await import('./cloudfile-api');
  const response = await cloudFileAPI.openLocalFile(repoID, path, mode);
  const result = response.data;
  if (!result || result.mode !== mode || typeof result.open_uri !== 'string') {
    throw new Error('服务未返回有效的 V2 本地编辑票据');
  }
  await launchPairedAgent(result.open_uri);
  return result;
}
