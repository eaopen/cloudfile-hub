import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { Simulate } from 'react-dom/test-utils';
import { seafileAPI } from '@/api/seafile-api';
import ResourceAnnotations from '../index';

jest.mock('@/api/seafile-api', () => ({ seafileAPI: {
  cloudFileResolveAnnotations: jest.fn(), cloudFileUpdateDescription: jest.fn(), cloudFileReplaceUserTags: jest.fn()
} }));
jest.mock('@/utils/constants', () => ({ gettext: text => text }));
jest.mock('@/utils/utils', () => ({ Utils: { getErrorMsg: error => error.message } }));

let root; let container;
const reference = { repo_id: 'repo', path: '/part', kind: 'file' };
const snapshot = {
  description: 'CAD', revision: 'revision-1', access: { read: true, write: true },
  tags: [
    { tag_id: 'sys', kind: 'system', label: 'System', enabled: true },
    { tag_id: 'user', kind: 'user', label: 'Drawing', enabled: true }
  ]
};
beforeEach(() => {
  jest.clearAllMocks();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(window.crypto, 'randomUUID', { value: () => 'fixture-request-key', configurable: true });
  seafileAPI.cloudFileResolveAnnotations.mockResolvedValue({ data: snapshot });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => { act(() => root.unmount()); container.remove(); });
async function render(path = '/part') {
  await act(async () => root.render(<ResourceAnnotations repoID="repo" path={path} kind="file" />));
}

test('loads only current resource tags and saves description with condition and idempotency key', async () => {
  await render();
  expect(seafileAPI.cloudFileResolveAnnotations).toHaveBeenCalledWith(reference);
  expect(container.querySelectorAll('textarea')[1].value).toBe('Drawing');
  expect(container.querySelector('li').textContent).toBe('System');
  const input = container.querySelector('textarea');
  act(() => Simulate.change(input, { target: { value: 'Edited' } }));
  seafileAPI.cloudFileUpdateDescription.mockResolvedValue({ data: {} });
  seafileAPI.cloudFileResolveAnnotations.mockResolvedValue({ data: { ...snapshot, description: 'Edited', revision: 'revision-2' } });
  await act(async () => container.querySelector('button').click());
  expect(seafileAPI.cloudFileUpdateDescription).toHaveBeenCalledWith(reference, 'revision-1', 'Edited', 'fixture-request-key');
  expect(input.value).toBe('Edited');
});

test('replaces only user labels and never submits system tags', async () => {
  await render();
  act(() => Simulate.change(container.querySelectorAll('textarea')[1], { target: { value: ' Drawing\n New ' } }));
  seafileAPI.cloudFileReplaceUserTags.mockResolvedValue({ data: {} });
  await act(async () => container.querySelectorAll('button')[1].click());
  expect(seafileAPI.cloudFileReplaceUserTags).toHaveBeenCalledWith(reference, 'revision-1',
    [{ label: 'Drawing' }, { label: 'New' }], 'fixture-request-key');
});

test('read-only access disables editing; stale or revoked writes show error without automatic retry', async () => {
  seafileAPI.cloudFileResolveAnnotations.mockResolvedValue({ data: { ...snapshot, access: { read: true, write: false } } });
  await render();
  expect([...container.querySelectorAll('button,textarea')].every(element => element.disabled)).toBe(true);
  seafileAPI.cloudFileResolveAnnotations.mockResolvedValue({ data: snapshot });
  await render('/other');
  seafileAPI.cloudFileUpdateDescription.mockRejectedValue(new Error('RESOURCE_REVISION_CONFLICT'));
  await act(async () => container.querySelector('button').click());
  expect(container.querySelector('[role="alert"]').textContent).toBe('RESOURCE_REVISION_CONFLICT');
  expect(seafileAPI.cloudFileUpdateDescription).toHaveBeenCalledTimes(1);
});

test('switching resource ignores a late response from the previous selection', async () => {
  let oldResponse;
  seafileAPI.cloudFileResolveAnnotations.mockReturnValueOnce(new Promise(resolve => { oldResponse = resolve; }));
  await render();
  seafileAPI.cloudFileResolveAnnotations.mockResolvedValue({ data: { ...snapshot, description: 'Current' } });
  await render('/other');
  await act(async () => oldResponse({ data: snapshot }));
  expect(container.querySelector('textarea').value).toBe('Current');
});
