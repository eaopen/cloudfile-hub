import { renderToStaticMarkup } from 'react-dom/server';
import { cloudFileAPI } from '../../cloudfile-api';
import DirACLPanel from '../dir-acl-panel';

jest.mock('@/utils/constants', () => ({ gettext: text => text }));
jest.mock('@/components/loading', () => () => null);
jest.mock('@/components/toast', () => ({ danger: jest.fn() }));
jest.mock('uuid', () => ({ v4: jest.fn(() => 'stable-request-key') }));
jest.mock('../../cloudfile-api', () => ({ cloudFileAPI: {
  listDirectoryPolicy: jest.fn(), createDirectoryPolicy: jest.fn(),
  replaceDirectoryRule: jest.fn(), deleteDirectoryPolicy: jest.fn(),
} }));

function panel() {
  const instance = new DirACLPanel({ repoID: 'library', path: '/folder' });
  instance.mounted = true;
  instance.setState = value => Object.assign(instance.state, typeof value === 'function' ? value(instance.state) : value);
  instance.state.provider = 'directory';
  return instance;
}
beforeEach(() => jest.clearAllMocks());

test('uncertain mutation retry keeps key and never creates ACL for a share', async () => {
  const instance = panel();
  instance.state.domain = 'shares';
  instance.state.subject = 'employee';
  cloudFileAPI.createDirectoryPolicy.mockRejectedValue(new Error('lost response'));
  instance.submit({ preventDefault() {} });
  await Promise.resolve(); await Promise.resolve();
  instance.submit({ preventDefault() {} });
  await Promise.resolve(); await Promise.resolve();
  expect(cloudFileAPI.createDirectoryPolicy).toHaveBeenCalledTimes(2);
  const first = cloudFileAPI.createDirectoryPolicy.mock.calls[0];
  expect(first).toEqual(cloudFileAPI.createDirectoryPolicy.mock.calls[1]);
  expect(first[1]).toEqual({ path: '/folder', subject: {
    type: 'user', provider: 'directory', namespace: 'user', external_id: 'employee',
  } });
  expect(first[2]).toBe('shares');
  expect(cloudFileAPI.replaceDirectoryRule).not.toHaveBeenCalled();
});

test('stale directory response cannot replace the newly selected folder', async () => {
  const instance = panel();
  let oldResolve;
  cloudFileAPI.listDirectoryPolicy.mockImplementation(() => new Promise(resolve => { oldResolve = resolve; }));
  instance.props.path = '/';
  const old = instance.load();
  cloudFileAPI.listDirectoryPolicy.mockResolvedValue({ data: { items: [], next_after: null, subject_provider: 'new' } });
  instance.props = { ...instance.props, path: '/current' };
  await instance.load();
  oldResolve({ data: { items: [{ id: 'stale' }], subject_provider: 'old' } });
  await old;
  expect(instance.state.provider).toBe('new');
  expect(instance.state.rules).toEqual([]);
});

test('sharing form exposes no permission or delegation controls', () => {
  const instance = panel();
  instance.state.loading = false;
  instance.state.domain = 'shares';
  const html = renderToStaticMarkup(instance.render());
  expect(html).toContain('Directory sharing');
  expect(html).not.toContain('id="cf-policy-permission"');
  expect(html).not.toContain('directory-admin');
  expect(html).toContain('Removing a share keeps directory rules.');
});


test('switching folders during pagination releases stale busy state', async () => {
  const instance = panel();
  let resolvePage;
  cloudFileAPI.listDirectoryPolicy.mockImplementationOnce(() => new Promise(resolve => { resolvePage = resolve; }));
  const oldPage = instance.more('rules');
  expect(instance.state.busy).toBe(true);
  cloudFileAPI.listDirectoryPolicy.mockResolvedValue({ data: { items: [], next_after: null, subject_provider: 'directory' } });
  instance.props = { ...instance.props, path: '/current' };
  await instance.load();
  resolvePage({ data: { items: [{ id: 'stale' }], next_after: null } });
  await oldPage;
  expect(instance.state.busy).toBe(false);
  expect(instance.state.rules).toEqual([]);
});
