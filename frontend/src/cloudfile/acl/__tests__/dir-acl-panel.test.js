import { renderToStaticMarkup } from 'react-dom/server';
import { cloudFileAPI } from '@/cloudfile/cloudfile-api';
import DirACLPanel from '../dir-acl-panel';

jest.mock('@/utils/constants', () => ({ gettext: text => text }));
jest.mock('@/components/loading', () => () => null);
jest.mock('@/components/toast', () => ({ danger: jest.fn() }));
jest.mock('uuid', () => ({ v4: jest.fn(() => 'stable-request-key') }));
jest.mock('@/cloudfile/cloudfile-api', () => ({ cloudFileAPI: {
  listDirectoryPolicy: jest.fn(), writeDirectoryRule: jest.fn(),
} }));

function panel() {
  const instance = new DirACLPanel({ repoID: 'library', path: '/folder' });
  instance.mounted = true;
  instance.setState = value => Object.assign(instance.state, typeof value === 'function' ? value(instance.state) : value);
  return instance;
}
beforeEach(() => jest.clearAllMocks());

test('uncertain unified ACL retry keeps key and sharing mode', async () => {
  const instance = panel();
  instance.state.subject = 'employee';
  cloudFileAPI.writeDirectoryRule.mockRejectedValue(new Error('lost response'));
  instance.submit({ preventDefault() {} });
  await Promise.resolve(); await Promise.resolve();
  instance.submit({ preventDefault() {} });
  await Promise.resolve(); await Promise.resolve();
  expect(cloudFileAPI.writeDirectoryRule).toHaveBeenCalledTimes(2);
  const first = cloudFileAPI.writeDirectoryRule.mock.calls[0];
  expect(first).toEqual(cloudFileAPI.writeDirectoryRule.mock.calls[1]);
  expect(first[0]).toEqual({ repo_id: 'library', path: '/folder', permission: 'r', inherit: true,
    share_mode: false, subject_type: 'user', namespace: 'user', external_id: 'employee',
    expected: null, revision: 'stable-request-key' });
});

test('stale directory response cannot replace the newly selected folder', async () => {
  const instance = panel();
  let oldResolve;
  cloudFileAPI.listDirectoryPolicy.mockImplementation(() => new Promise(resolve => { oldResolve = resolve; }));
  instance.props.path = '/';
  const old = instance.load();
  cloudFileAPI.listDirectoryPolicy.mockResolvedValue({ data: { data: [] } });
  instance.props = { ...instance.props, path: '/current' };
  await instance.load();
  oldResolve({ data: { data: [{ external_id: 'stale' }] } });
  await old;
  expect(instance.state.rules).toEqual([]);
});

test('unified form exposes permission and sharing without a separate share editor', () => {
  const instance = panel();
  instance.state.loading = false;
  const html = renderToStaticMarkup(instance.render());
  expect(html).toContain('Directory sharing');
  expect(html).toContain('id="cf-policy-permission"');
  expect(html).not.toContain('directory-admin');
  expect(html).toContain('Allow access without library membership');
  expect(html).not.toContain('cf-policy-domain');
});


test('root ACL never enables directory sharing', async () => {
  const instance = panel();
  instance.props.path = '/';
  instance.state.subject = 'employee';
  cloudFileAPI.writeDirectoryRule.mockRejectedValue(new Error('lost response'));
  instance.submit({ preventDefault() {} });
  await Promise.resolve(); await Promise.resolve();
  expect(cloudFileAPI.writeDirectoryRule.mock.calls[0][0].share_mode).toBe(false);
});


test('editing and deletion compare the current row revision', async () => {
  const instance = panel();
  const rule = { repo_id: 'library', path: '/folder', subject_type: 'org', namespace: 'directory',
    external_id: 'team', permission: 'r', inherit: true, share_mode: true, revision: 'old-revision' };
  cloudFileAPI.writeDirectoryRule.mockRejectedValue(new Error('conflict'));
  instance.remove('rules', rule);
  await Promise.resolve(); await Promise.resolve();
  expect(cloudFileAPI.writeDirectoryRule.mock.calls[0]).toEqual([
    { ...rule, expected: 'old-revision', revision: 'stable-request-key' }, true
  ]);
});
