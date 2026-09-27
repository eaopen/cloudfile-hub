import { seafileAPI } from '../seafile-api';

jest.mock('@/utils/constants', () => ({ siteRoot: '/', cloudFileWebEnabled: true }));
jest.mock('axios', () => ({ create: jest.fn(() => ({ get: jest.fn(), post: jest.fn() })) }));

beforeEach(() => {
  seafileAPI.req.get.mockReset();
  seafileAPI.req.post.mockReset();
  global.fetch = jest.fn();
});

test('single-use read ticket is sent only as bearer, with cookies omitted', async () => {
  seafileAPI.req.post.mockResolvedValue({ data: { ticket: 'fixture-ticket' } });
  const bytes = new Blob(['content']);
  fetch.mockResolvedValue({ ok: true, blob: async () => bytes });
  expect((await seafileAPI.cloudFileRead('repo', '/file.txt')).data).toBe(bytes);
  expect(seafileAPI.req.post.mock.calls[0][1]).toEqual({ reference: { repo_id: 'repo', path: '/file.txt', kind: 'file' } });
  expect(fetch).toHaveBeenCalledWith('/seafhttp/cloudfile/read', {
    headers: { Authorization: 'Bearer fixture-ticket' }, credentials: 'omit', redirect: 'error'
  });
});

test.each([false, true])('explicit multipart upload uses current head and operation replace=%s', async replace => {
  const file = new File(['new'], 'part.txt');
  const entry = { name: 'part.txt', type: 'file', id: 'object' };
  seafileAPI.req.get.mockResolvedValueOnce({ data: { head_id: 'a'.repeat(40) } })
    .mockResolvedValueOnce({ data: { dirent_list: [entry] } });
  seafileAPI.req.post.mockResolvedValue({ data: { object_id: 'object' } });
  expect(await seafileAPI.cloudFileUpload('repo', '/', file, replace)).toEqual(entry);
  const [url, form] = seafileAPI.req.post.mock.calls[0];
  expect(url.endsWith(replace ? '/manual-update/' : '/manual-upload/')).toBe(true);
  expect(form.get('path')).toBe('/part.txt');
  expect(form.get('head_id')).toBe('a'.repeat(40));
  expect(form.get('file')).toBe(file);
  expect(seafileAPI.req.get.mock.calls[0][1].params).toEqual({ p: '/' });
});

test('missing current head cannot publish and thumbnails stay out of browse requests', async () => {
  seafileAPI.req.get.mockResolvedValue({ data: {} });
  await expect(seafileAPI.cloudFileUpload('repo', '/', new File(['x'], 'a'), false)).rejects.toThrow();
  expect(seafileAPI.req.post).not.toHaveBeenCalled();
  await seafileAPI.listDir('repo', '/', { with_thumbnail: true });
  expect(seafileAPI.req.get.mock.calls[1][1].params).toEqual({ p: '/' });
});

test('unconfirmed publication is not retried automatically', async () => {
  seafileAPI.req.get.mockResolvedValue({ data: { head_id: 'a'.repeat(40) } });
  seafileAPI.req.post.mockRejectedValue(new Error('PUBLICATION_UNCONFIRMED'));
  await expect(seafileAPI.cloudFileUpload('repo', '/', new File(['x'], 'a'), true)).rejects.toThrow();
  expect(seafileAPI.req.post).toHaveBeenCalledTimes(1);
});

test('local logout is an empty CSRF-client POST and requires a confirmed response', async () => {
  seafileAPI.req.post.mockResolvedValueOnce({ data: { local_logged_out: true, idp_logged_out: false } });
  await seafileAPI.cloudFileLogout();
  expect(seafileAPI.req.post).toHaveBeenCalledWith('/api/v2.1/cloudfile/extensions/identity/v1/logout/', null);
  seafileAPI.req.post.mockResolvedValueOnce({ data: { local_logged_out: false } });
  await expect(seafileAPI.cloudFileLogout()).rejects.toThrow('Local logout was not confirmed');
});
