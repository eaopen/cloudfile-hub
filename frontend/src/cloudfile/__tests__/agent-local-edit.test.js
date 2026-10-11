/**
 * @jest-environment jsdom
 * @jest-environment-options {"url":"https://cloudfile.invalid/"}
 */
import { launchPairedAgent, CLOUDFILE_EXTENSION_ID } from '../agent-local-edit';
import { cloudFileAPI } from '../cloudfile-api';

jest.mock('@/utils/constants', () => ({ siteRoot: '/' }));
jest.mock('axios', () => ({ create: jest.fn(() => ({ post: jest.fn() })) }));
jest.mock('js-cookie', () => ({ get: jest.fn(() => 'csrf-fixture') }));

beforeEach(() => {
  cloudFileAPI.req.post.mockReset();
  window.chrome = { runtime: { sendMessage: jest.fn(), lastError: undefined } };
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
