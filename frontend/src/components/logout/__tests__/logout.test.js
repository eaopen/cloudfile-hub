import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { seafileAPI } from '@/api/seafile-api';
import toaster from '../../toast';
import Logout from '../index';

let mockCloudFileEnabled = true;
jest.mock('@/utils/constants', () => ({ get cloudFileWebEnabled() { return mockCloudFileEnabled; }, siteRoot: '/', gettext: text => text }));
jest.mock('@/api/seafile-api', () => ({ seafileAPI: { cloudFileLogout: jest.fn() } }));
jest.mock('@/utils/utils', () => ({ Utils: { getErrorMsg: error => error.message } }));
jest.mock('../../icon', () => () => null);
jest.mock('../../toast', () => ({ danger: jest.fn() }));

let root; let container; let loggedOut;
beforeEach(() => {
  mockCloudFileEnabled = true;
  seafileAPI.cloudFileLogout.mockReset();
  toaster.danger.mockReset();
  loggedOut = jest.fn();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

test('both icon/menu use confirmed POST before leaving the authenticated page', async () => {
  let confirm;
  seafileAPI.cloudFileLogout.mockReturnValue(new Promise(resolve => { confirm = resolve; }));
  act(() => root.render(<Logout className="item" onLoggedOut={loggedOut}>Log out</Logout>));
  const button = container.querySelector('button');
  await act(async () => { button.click(); button.click(); });
  expect(seafileAPI.cloudFileLogout).toHaveBeenCalledTimes(1);
  expect(button.disabled).toBe(true);
  expect(loggedOut).not.toHaveBeenCalled();
  await act(async () => confirm({ data: { local_logged_out: true } }));
  expect(loggedOut).toHaveBeenCalledTimes(1);
});

test('failed logout stays on the page, shows failure and permits explicit retry', async () => {
  seafileAPI.cloudFileLogout.mockRejectedValue(new Error('Session service unavailable'));
  act(() => root.render(<Logout onLoggedOut={loggedOut} />));
  await act(async () => container.querySelector('button').click());
  expect(loggedOut).not.toHaveBeenCalled();
  expect(toaster.danger).toHaveBeenCalledWith('Session service unavailable');
  expect(container.querySelector('button').disabled).toBe(false);
});

test('ordinary CE mode retains its existing logout link', () => {
  mockCloudFileEnabled = false;
  act(() => root.render(<Logout onLoggedOut={loggedOut} />));
  expect(container.querySelector('a').getAttribute('href')).toBe('/accounts/logout/');
  expect(seafileAPI.cloudFileLogout).not.toHaveBeenCalled();
});
