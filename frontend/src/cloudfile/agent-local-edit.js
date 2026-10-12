// The ID is derived from the stable public key in
// cloudfile-chrome-extension/manifest.json, not from a privileged browser API.
// The extension still validates sender origin, paired device and session URI.
// Windows uses the SINGLE com.cloudfile.current_agent Native Host.
export const CLOUDFILE_EXTENSION_ID = 'gocnpbhnbikcpnlafmodflddgnmfcjoc';

export function launchPairedAgent(openURI) {
  return new Promise((resolve, reject) => {
    const runtime = typeof window !== 'undefined' && window.chrome && window.chrome.runtime;
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
