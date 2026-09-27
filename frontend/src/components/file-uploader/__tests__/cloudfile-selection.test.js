import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { seafileAPI } from '@/api/seafile-api';
import FileUploader from '../file-uploader';

jest.mock('@/utils/constants', () => ({ cloudFileWebEnabled: true, gettext: text => text }));
jest.mock('@/api/seafile-api', () => ({ seafileAPI: { cloudFileUpload: jest.fn() } }));
jest.mock('@/utils/utils', () => ({ Utils: { getErrorMsg: error => error.message } }));
jest.mock('../../toast', () => ({ success: jest.fn(), danger: jest.fn() }));
jest.mock('../upload-progress-dialog', () => () => null);
jest.mock('../../dialog/upload-remind-dialog', () => props => (
  <div><button onClick={props.replaceRepetitionFile}>Replace</button>
    <button onClick={props.cancelFileUpload}>Cancel</button>
  </div>
));

let root; let container;
beforeEach(() => {
  seafileAPI.cloudFileUpload.mockReset();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});
const select = async file => {
  const input = container.querySelector('input');
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
};
const click = async text => {
  const button = [...container.querySelectorAll('button')].find(item => item.textContent === text);
  await act(async () => button.click());
};

test('explicit new file selection uploads once and updates the existing list', async () => {
  const done = jest.fn();
  const entry = { name: 'part.txt', type: 'file' };
  seafileAPI.cloudFileUpload.mockResolvedValue(entry);
  act(() => root.render(<FileUploader repoID="repo" path="/parts" direntList={[]} dragAndDrop={false} onFileUploadSuccess={done} />));
  const file = new File(['new'], 'part.txt');
  await select(file);
  expect(done).toHaveBeenCalledWith(entry);
  expect(seafileAPI.cloudFileUpload).toHaveBeenCalledWith('repo', '/parts', file, false);
  expect(seafileAPI.cloudFileUpload).toHaveBeenCalledTimes(1);
});

test('existing file requires Replace; Cancel performs no write', async () => {
  seafileAPI.cloudFileUpload.mockResolvedValue({ name: 'part.txt', type: 'file' });
  act(() => root.render(<FileUploader repoID="repo" path="/" direntList={[{ name: 'part.txt', type: 'file' }]} dragAndDrop={false} onFileUploadSuccess={() => {}} />));
  const file = new File(['new'], 'part.txt');
  await select(file);
  expect(seafileAPI.cloudFileUpload).not.toHaveBeenCalled();
  await click('Cancel');
  expect(seafileAPI.cloudFileUpload).not.toHaveBeenCalled();
  await select(file);
  await click('Replace');
  expect(seafileAPI.cloudFileUpload).toHaveBeenCalledTimes(1);
  expect(seafileAPI.cloudFileUpload).toHaveBeenCalledWith('repo', '/', file, true);
});
