"""Finish asynchronous first login in the browser without exposing proof URLs."""
import json
import secrets

from django.http import HttpResponse


def pending_page(token, site_root):
    # The callback validates the opaque proof. Keep it only in this page's
    # memory: query strings, persistent storage and referrers outlive the flow.
    prefix = site_root + 'api/v2.1/cloudfile/extensions/identity/v1/'
    config = json.dumps(dict(token=token, pending=prefix + 'pending/', begin=prefix + 'begin/'))
    config = config.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    nonce = secrets.token_urlsafe(24)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudFile sign in</title><body>
<main><h1>Signing in to CloudFile</h1>
<p id="status" role="status">Preparing your account and permissions…</p>
<button id="retry" type="button" hidden>Retry sign in</button></main>
<script nonce="NONCE">
(() => {
  const flow = CONFIG;
  const message = document.getElementById('status');
  const retry = document.getElementById('retry');
  retry.onclick = () => window.location.replace(flow.begin);
  const deadline = Date.now() + 120000;
  async function poll() {
    try {
      const reply = await fetch(flow.pending, {credentials: 'same-origin', cache: 'no-store',
        headers: {Authorization: 'CloudFilePending ' + flow.token, Accept: 'application/json'}});
      if (!reply.ok) throw new Error('pending unavailable');
      const result = await reply.json();
      if (result.status === 'succeeded') { window.location.replace(flow.begin); return; }
      if (!['queued', 'running'].includes(result.status) || Date.now() >= deadline)
        throw new Error('provisioning incomplete');
      window.setTimeout(poll, 1000);
    } catch (_) {
      message.textContent = 'Account preparation is not complete. Please retry sign in.';
      retry.hidden = false;
    }
  }
  poll();
})();
</script></body></html>'''.replace('NONCE', nonce).replace('CONFIG', config)
    response = HttpResponse(page, status=202)
    response['Content-Security-Policy'] = (
        "default-src 'none'; script-src 'nonce-" + nonce + "'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'self'")
    return response
