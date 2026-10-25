import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import LocalFileDialog from '..';
import { cloudFileAPI } from '@/cloudfile/cloudfile-api';

jest.mock('@/utils/constants', () => ({ gettext: s => s }));
jest.mock('@/cloudfile/cloudfile-api', () => ({ cloudFileAPI: { getLocalCheckoutInfo: jest.fn() } }));
jest.mock('@/cloudfile/agent-local-edit', () => ({ openV2LocalFile: jest.fn() }));
jest.mock('reactstrap', () => {
  const React = require('react');
  return {
    Modal: ({ children }) => <div>{children}</div>,
    ModalHeader: ({ children }) => <h2>{children}</h2>,
    ModalBody: ({ children }) => <div>{children}</div>,
    Button: props => <button {...props} />,
  };
}, { virtual: true });

let container, root, onOpen, onClose;
const supported = { checkout_supported: true, checked_out: false };
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  onOpen = jest.fn().mockResolvedValue({});
  onClose = jest.fn();
  cloudFileAPI.getLocalCheckoutInfo.mockReset().mockResolvedValue({ data: supported });
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});
const render = async (props = {}) => {
  await act(async () => root.render(<LocalFileDialog repoID="repo" path="/file.docx"
    permission="rw" onOpen={onOpen} onClose={onClose} {...props} />));
};
const buttons = () => [...container.querySelectorAll('button')];
const click = async index => act(async () => buttons()[index].click());

test.each(['local-view', 'optimistic-edit', 'exclusive-edit'])('explicitly selects %s without guessing by extension', async mode => {
  await render();
  await click(['local-view', 'optimistic-edit', 'exclusive-edit'].indexOf(mode));
  expect(onOpen).toHaveBeenCalledTimes(1);
  expect(onOpen).toHaveBeenCalledWith({ repoID: 'repo', path: '/file.docx', mode });
  expect(onClose).toHaveBeenCalledTimes(1);
});

test.each(['r', 'invisible', undefined])('permission %s never offers write operations', async permission => {
  await render({ permission });
  expect(buttons().map(b => b.disabled)).toEqual([permission !== 'r', true, true]);
  await click(1);
  await click(2);
  expect(onOpen).not.toHaveBeenCalled();
});

test('a read-only library still offers local viewing', async () => {
  await render({ readOnly: true });
  expect(buttons().map(b => b.disabled)).toEqual([false, true, true]);
});

test.each([null, { checkout_supported: false, checked_out: false }])('unconfirmed or unsupported Guard affects only exclusive editing', async data => {
  cloudFileAPI.getLocalCheckoutInfo.mockResolvedValue({ data });
  await render();
  expect(buttons().map(b => b.disabled)).toEqual([false, false, true]);
});

test('an unconfirmed lock state blocks new write tasks, not local viewing', async () => {
  cloudFileAPI.getLocalCheckoutInfo.mockRejectedValue(new Error('offline'));
  await render();
  expect(buttons().map(b => b.disabled)).toEqual([false, true, true]);
  expect(container.textContent).toContain('lock state could not be confirmed');
  await click(1);
  await click(2);
  expect(onOpen).not.toHaveBeenCalled();
});

test('a 503 lock-info response is unknown, not "not checked out"', async () => {
  cloudFileAPI.getLocalCheckoutInfo.mockRejectedValue({ response: { status: 503, data: { code: 'EDIT_UNAVAILABLE' } } });
  await render();
  expect(buttons().map(b => b.disabled)).toEqual([false, true, true]);
  await click(1);
  expect(onOpen).not.toHaveBeenCalled();
});

test("another user's active Guard blocks new write tasks", async () => {
  cloudFileAPI.getLocalCheckoutInfo.mockResolvedValue({
    data: { ...supported, checked_out: true, checked_out_by_me: false },
  });
  await render();
  expect(buttons().map(b => b.disabled)).toEqual([false, true, true]);
  expect(container.textContent).toContain('checked out by another user');
  expect(container.textContent).toContain('existing Agent2 task');
});

test('the Guard owner can resume the existing exclusive task', async () => {
  cloudFileAPI.getLocalCheckoutInfo.mockResolvedValue({
    data: { ...supported, checked_out: true, checked_out_by_me: true },
  });
  await render();
  expect(buttons().map(b => b.disabled)).toEqual([false, true, false]);
  expect(buttons()[2].textContent).toBe('Resume exclusive editing');
  expect(container.textContent).toContain('Resume the existing Agent2 task');
  await click(2);
  expect(onOpen).toHaveBeenCalledWith({ repoID: 'repo', path: '/file.docx', mode: 'exclusive-edit' });
});

test.each([
  [{ response: { status: 403, data: { code: 'EDIT_DENIED' } } }, 'Access denied'],
  [{ response: { data: { code: 'CHECKOUT_UNSUPPORTED' } } }, 'Exclusive editing is unavailable'],
  [new Error('lost native reply'), 'Check the Agent2 task center'],
])('refusal or unknown handoff does not downgrade or retry', async (error, message) => {
  onOpen.mockRejectedValue(error);
  await render();
  await click(2);
  expect(onOpen).toHaveBeenCalledTimes(1);
  expect(onClose).not.toHaveBeenCalled();
  expect(container.querySelector('[role="alert"]').textContent).toContain(message);
});

test('rapid repeated clicks create only one handoff', async () => {
  let finish;
  onOpen.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  await render();
  await act(async () => { buttons()[0].click(); buttons()[0].click(); });
  expect(onOpen).toHaveBeenCalledTimes(1);
  expect(buttons().every(b => b.disabled)).toBe(true);
  await act(async () => finish({}));
});
