import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';

jest.mock('@/components/local-file-dialog', () => function Dialog(props) {
  return <button data-testid="mode" onClick={() => props.onOpen({ path: props.path, mode: 'exclusive-edit' })}>{props.permission}</button>;
});
jest.mock('@/utils/constants', () => ({ gettext: s => s }));
jest.mock('../index.css', () => ({}));
for (const path of [
  '@/components/dirent-operation-menu/contextMenuUtils', '@/components/dirent-operation-menu/menuHandlers',
  '@/components/dropdown', '@/components/icon', '@/components/op-element', '@/components/op-icon', '@/components/tooltip',
  '@/constants/event-bus-type', '@/features/metadata/constants', '@/models', '@/utils/event-bus',
]) jest.doMock(path, () => ({ __esModule: true, default: () => null }));
jest.doMock('@/utils/utils', () => ({ Utils: { joinPath: (...parts) => parts.join('/').replace(/\/+/g, '/') } }));
const Toolbar = require('..').default;
class TestToolbar extends Toolbar {
  constructor(props) {
    super(props);
    this.getSelectedDirentOperations = () => ({ iconOps: [], menuOps: [] });
    this.getSelectedDirentsOperations = () => ({ iconOps: [], menuOps: [] });
  }
}

let container, root;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  jest.restoreAllMocks();
});

test.each([['r', 'rw'], ['rw', 'r']])('file permission %s overrides parent %s and forwards the selected mode', async (permission, userPerm) => {
  const onOpen = jest.fn();
  const noop = () => {};
  await act(async () => root.render(<TestToolbar repoID="repo" path="/folder" userPerm={userPerm}
    selectedDirentList={[{ name: 'a.docx', type: 'file', id: 'id', permission }]}
    currentRepoInfo={{}} eventBus={{}} onItemsDelete={noop} unSelectDirent={noop}
    updateDirent={noop} direntList={[]} showDirentDetail={noop} onCloudFileLocalEdit={onOpen} />));
  await act(async () => [...container.querySelectorAll('button')].find(b => b.textContent === 'Local file operations').click());
  const mode = container.querySelector('[data-testid="mode"]');
  expect(mode.textContent).toBe(permission);
  await act(async () => mode.click());
  expect(onOpen).toHaveBeenCalledWith('/folder/a.docx', 'exclusive-edit');
});
