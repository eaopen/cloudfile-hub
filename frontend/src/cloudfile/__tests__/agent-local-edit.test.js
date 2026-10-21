/**
 * @jest-environment jsdom
 * @jest-environment-options {"url":"https://cloudfile.invalid/"}
 */
import {
  launchPairedAgent, openV2LocalFile, CLOUDFILE_EXTENSION_ID,
} from '../agent-local-edit';
import * as agentLocalEdit from '../agent-local-edit';
import { cloudFileAPI } from '../cloudfile-api';

jest.mock('@/utils/constants', () => ({ siteRoot: '/' }));
jest.mock('axios', () => ({ create: jest.fn(() => ({ post: jest.fn(), get: jest.fn() })) }));
jest.mock('js-cookie', () => ({ get: jest.fn(() => 'csrf-fixture') }));

const SESSION = '11111111-1111-4111-8111-111111111111';
const URI = 'cloudfile-open://v2/open?instance=https%3A%2F%2Fcloudfile.invalid&session=' +
  SESSION + '&ticket=header.payload.signature';

beforeEach(() => {
  cloudFileAPI.req.post.mockReset();
  window.chrome = { runtime: { sendMessage: jest.fn(), lastError: undefined } };
});

test('ordinary local edit uses the current V2 scoped endpoint', async () => {
  cloudFileAPI.req.post.mockResolvedValueOnce({ data: { mode: 'optimistic-edit', open_uri: URI } });
  await cloudFileAPI.openLocalFile('repo-id', '/Drawing.dwg', 'optimistic-edit');
  expect(cloudFileAPI.req.post.mock.calls[0]).toEqual([
    '/api/v2.1/cloudfile/edit/v1/open/',
    { repo_id: 'repo-id', path: '/Drawing.dwg', mode: 'optimistic-edit' },
  ]);
  await cloudFileAPI.openLocalFile('repo-id', '/Drawing.dwg', 'local-view');
  expect(cloudFileAPI.req.post.mock.calls[1][1].mode).toBe('local-view');
});

test('openV2LocalFile hands the scoped URI to the fixed extension exactly once', async () => {
  cloudFileAPI.req.post.mockResolvedValueOnce({ data: { mode: 'optimistic-edit', open_uri: URI } });
  window.chrome.runtime.sendMessage.mockImplementation((id, message, callback) => {
    expect(id).toBe(CLOUDFILE_EXTENSION_ID);
    expect(message).toEqual({ type: 'open_uri', uri: URI });
    callback({ ok: true });
  });
  await expect(openV2LocalFile({ repoID: 'repo-id', path: '/Drawing.dwg' }))
    .resolves.toEqual({ mode: 'optimistic-edit', open_uri: URI });
  expect(window.chrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
});

test('openV2LocalFile refuses a mismatched mode without touching the extension', async () => {
  cloudFileAPI.req.post.mockResolvedValueOnce({ data: { mode: 'local-view', open_uri: URI } });
  await expect(openV2LocalFile({ repoID: 'repo-id', path: '/Drawing.dwg' })).rejects.toThrow('V2');
  expect(window.chrome.runtime.sendMessage).not.toHaveBeenCalled();
});

test('V2 launch sends only exact same-origin Agent2 JWT URI to fixed extension', async () => {
  window.chrome.runtime.sendMessage.mockImplementation((id, message, callback) => {
    expect(id).toBe(CLOUDFILE_EXTENSION_ID);
    expect(message).toEqual({ type: 'open_uri', uri: URI });
    callback({ ok: true });
  });
  await expect(launchPairedAgent(URI)).resolves.toEqual({ accepted: true });
  expect(window.chrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
});

test('V2 rejects legacy URI, foreign origin and malformed ticket before native message', async () => {
  for (const uri of [
    'cloudfile-open://v1/open?instance=https%3A%2F%2Fcloudfile.invalid&session=x&ticket=y',
    'cloudfile-open://v2/open?instance=https%3A%2F%2Fevil.invalid&session=' + SESSION + '&ticket=h.p.s',
    'cloudfile-open://v2/open?instance=https%3A%2F%2Fcloudfile.invalid&session=' + SESSION + '&ticket=x',
  ]) {
    await expect(launchPairedAgent(uri)).rejects.toThrow();
  }
  expect(window.chrome.runtime.sendMessage).not.toHaveBeenCalled();
});

test('uncertain V2 Agent2 open never retries the browser ticket', async () => {
  window.chrome.runtime.sendMessage.mockImplementation((_id, _message, callback) => callback(null));
  await expect(launchPairedAgent(URI)).rejects.toThrow('未确认');
  expect(window.chrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
});

test('legacy device pairing helpers are no longer exported', () => {
  expect(agentLocalEdit.ensurePairedLocalAgent).toBeUndefined();
  expect(agentLocalEdit.pairRequest).toBeUndefined();
});
