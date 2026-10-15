/**
 * @jest-environment jsdom
 * @jest-environment-options {"url":"https://cloudfile.invalid/"}
 */
import {
  ensurePairedLocalAgent, launchPairedAgent, CLOUDFILE_EXTENSION_ID,
} from '../agent-local-edit';
import { cloudFileAPI } from '../cloudfile-api';

jest.mock('@/utils/constants', () => ({ siteRoot: '/' }));
jest.mock('axios', () => ({ create: jest.fn(() => ({ post: jest.fn() })) }));
jest.mock('js-cookie', () => ({ get: jest.fn(() => 'csrf-fixture') }));

const DEVICE = '11111111-1111-4111-8111-111111111111';

// The extension answers each external message; fetch answers the page's own
// same-origin CloudFile calls. Both are asserted by call shape, not just result.
function pairExtension(handler) {
  window.chrome.runtime.sendMessage.mockImplementation((id, message, callback) => {
    expect(id).toBe(CLOUDFILE_EXTENSION_ID);
    Promise.resolve(handler(message)).then(callback);
  });
}

function pairFetch(routes) {
  global.fetch = jest.fn(async (url, options) => {
    const operation = String(url).split('/devices/')[1].replace(/\/$/, '');
    const route = routes[operation];
    expect(options.method).toBe('POST');
    expect(options.credentials).toBe('same-origin');
    expect(options.headers['X-CSRFToken']).toBe('csrf-fixture');
    if (!route) throw new Error('unexpected ' + operation);
    return { ok: route.ok, status: route.status, json: async () => route.body };
  });
}

beforeEach(() => {
  cloudFileAPI.req.post.mockReset();
  window.chrome = { runtime: { sendMessage: jest.fn(), lastError: undefined } };
  document.cookie = 'sfcsrftoken=csrf-fixture';
});

test('Web only requests paired device list and ordinary edit session', async () => {
  cloudFileAPI.req.post.mockResolvedValueOnce({ data: { devices: [{ device_id: 'id' }] } })
    .mockResolvedValueOnce({ data: { state: 'created' } });
  const listed = await cloudFileAPI.listLocalEditingDevices();
  expect(listed.data.devices).toHaveLength(1);
  const ref = { repo_id: 'repo', path: '/Drawing.dwg', kind: 'file' };
  await cloudFileAPI.startOrdinaryAgentEdit(ref, 'device');
  expect(cloudFileAPI.req.post.mock.calls[0]).toEqual([
    '/api/v2.1/cloudfile/extensions/local-edit/v1/devices/list/', {}
  ]);
  expect(cloudFileAPI.req.post.mock.calls[1]).toEqual([
    '/api/v2.1/cloudfile/extensions/local-edit/v1/sessions/create/',
    { reference: ref, device_id: 'device', mode: 'optimistic-edit' }
  ]);
});

test('an already paired machine reuses the device after a server ownership check', async () => {
  pairExtension(async () => ({ ok: true, state: 'paired', device_id: DEVICE }));
  pairFetch({ status: { ok: true, status: 200, body: { device_id: DEVICE, state: 'active' } } });
  await expect(ensurePairedLocalAgent({ servicePath: '/seafile' }))
    .resolves.toEqual({ device_id: DEVICE, paired: true });
  // No new registration: only the ownership probe runs.
  const types = window.chrome.runtime.sendMessage.mock.calls.map(call => call[1].type);
  expect(types).toEqual(['pair_prepare']);
  expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(String(global.fetch.mock.calls[0][0]))
    .toBe('https://cloudfile.invalid/seafile/api/v2.1/cloudfile/extensions/local-edit/v1/devices/status/');
  expect(window.chrome.runtime.sendMessage.mock.calls[0][1]).toEqual({
    type: 'pair_prepare', server: 'https://cloudfile.invalid', service_path: '/seafile',
  });
});

test('first local edit pairs once through the page session and returns its device', async () => {
  const challenge = {
    device_id: DEVICE, state: 'pending', revision: '1',
    key_thumbprint: 'thumb', challenge: { device_id: DEVICE, operation: 'pair' },
  };
  pairExtension(async (message) => {
    if (message.type === 'pair_prepare') {
      return { ok: true, state: 'pending', enrollment: { public_key: { kty: 'EC' } } };
    }
    if (message.type === 'pair_sign') {
      expect(message.response.device_id).toBe(DEVICE);
      return { ok: true, proof: { device_id: DEVICE, nonce: 'n', signature: 's' } };
    }
    expect(message.response.state).toBe('active');
    return { ok: true };
  });
  pairFetch({
    'pair-start': { ok: true, status: 200, body: challenge },
    'pair-confirm': { ok: true, status: 200, body: { device_id: DEVICE, state: 'active', revision: '2' } },
  });
  await expect(ensurePairedLocalAgent({ servicePath: '' }))
    .resolves.toEqual({ device_id: DEVICE, paired: false });
  const types = window.chrome.runtime.sendMessage.mock.calls.map(call => call[1].type);
  expect(types).toEqual(['pair_prepare', 'pair_sign', 'pair_confirm']);
  // The page signed with its own CSRF token; no token is ever sent to the Agent.
  expect(global.fetch).toHaveBeenCalledTimes(2);
  expect(JSON.stringify(window.chrome.runtime.sendMessage.mock.calls))
    .not.toContain('csrf-fixture');
});

test('a device bound to another account is refused instead of silently reused', async () => {
  pairExtension(async () => ({ ok: true, state: 'paired', device_id: DEVICE }));
  pairFetch({ status: { ok: false, status: 403, body: {} } });
  await expect(ensurePairedLocalAgent({ servicePath: '' })).rejects.toThrow('其他账号');
});

test('a missing extension or login never starts a pairing request', async () => {
  window.chrome.runtime.sendMessage.mockImplementation((_id, _message, callback) =>
    callback({ ok: false, error: 'Agent 未响应' }));
  pairFetch({});
  await expect(ensurePairedLocalAgent({ servicePath: '' })).rejects.toThrow('Agent 未响应');
  expect(global.fetch).not.toHaveBeenCalled();
});

test('fixed extension launches exact opaque one-use session URI without any local file path', async () => {
  const uri = 'cloudfile-open://v1/open?instance=https%3A%2F%2Fcloudfile.invalid&session=session&ticket=one-time';
  window.chrome.runtime.sendMessage.mockImplementation((id, message, callback) => {
    expect(id).toBe(CLOUDFILE_EXTENSION_ID);
    expect(message).toEqual({ type: 'open_uri', uri });
    callback({ ok: true });
  });
  await expect(launchPairedAgent(uri)).resolves.toEqual({ accepted: true });
  expect(window.chrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
  expect(CLOUDFILE_EXTENSION_ID).toBe('gocnpbhnbikcpnlafmodflddgnmfcjoc');
});

test('uncertain native result never retries a one-use ticket', async () => {
  window.chrome.runtime.sendMessage.mockImplementation((_id, _message, callback) => callback(null));
  await expect(launchPairedAgent(
    'cloudfile-open://v1/open?instance=https%3A%2F%2Fcloudfile.invalid&session=s&ticket=t'
  )).rejects.toThrow('结果未确认');
  expect(window.chrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
});

test('untrusted scheme cannot contact native host', async () => {
  await expect(launchPairedAgent('https://malicious.invalid/')).rejects.toThrow();
  expect(window.chrome.runtime.sendMessage).not.toHaveBeenCalled();
});
