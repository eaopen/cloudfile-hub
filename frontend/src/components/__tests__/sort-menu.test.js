import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SortMenu, { DIRECTORY_SORT_OPTIONS, filterSortOptions } from '@/components/sort-menu';

jest.mock('@/utils/constants', () => ({ gettext: (text) => text }));
jest.mock('@/components/icon', () => ({ __esModule: true, default: () => null }));
jest.mock('@/components/tooltip', () => ({ __esModule: true, default: () => null }));
jest.mock('@/components/dropdown', () => {
  const React = require('react');
  const MockDropdown = ({ items }) => (
    <ul>{items.map((item) => <li key={item.key}>{item.label}</li>)}</ul>
  );
  MockDropdown.displayName = 'MockDropdown';
  return { __esModule: true, default: MockDropdown };
});

const DEFAULT_VALUES = ['name-asc', 'name-desc', 'size-asc', 'size-desc', 'time-asc', 'time-desc'];
const EXT_VALUES = ['ext-asc', 'ext-desc'];

describe('directory sort options', () => {
  test('offers extension sorting only for a complete listing', () => {
    expect(filterSortOptions(DIRECTORY_SORT_OPTIONS, true).map((option) => option.value)).toEqual([
      ...DEFAULT_VALUES, ...EXT_VALUES,
    ]);
  });

  test('a server-paged listing fails closed without extension sorting', () => {
    expect(filterSortOptions(DIRECTORY_SORT_OPTIONS, false).map((option) => option.value)).toEqual(DEFAULT_VALUES);
    expect(filterSortOptions(DIRECTORY_SORT_OPTIONS, undefined).map((option) => option.value)).toEqual(DEFAULT_VALUES);
  });
});

describe('SortMenu', () => {
  let container;
  let root;

  const renderMenu = async (props = {}) => {
    await act(async () => {
      root.render(
        <SortMenu sortBy="name" sortOrder="asc" onSelectSortOption={() => {}} {...props} />
      );
    });
  };

  const labels = () => [...container.querySelectorAll('li')].map((li) => li.textContent);

  beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  test('shows type sorting for a complete directory listing', async () => {
    await renderMenu({ sortOptions: DIRECTORY_SORT_OPTIONS, isCompleteList: true });

    expect(labels()).toContain('Ascending by type');
    expect(labels()).toContain('Descending by type');
  });

  test('hides type sorting for a paged listing', async () => {
    await renderMenu({ sortOptions: DIRECTORY_SORT_OPTIONS, isCompleteList: false });

    expect(labels()).toEqual([
      'Ascending by name', 'Descending by name',
      'Ascending by size', 'Descending by size',
      'Ascending by time', 'Descending by time',
    ]);
  });

  test('hides type sorting by default when completeness is not declared', async () => {
    await renderMenu({ sortOptions: DIRECTORY_SORT_OPTIONS });

    expect(labels()).not.toContain('Ascending by type');
  });

  test('default consumers are unaffected', async () => {
    await renderMenu({});

    expect(labels()).toEqual([
      'Ascending by name', 'Descending by name',
      'Ascending by size', 'Descending by size',
      'Ascending by time', 'Descending by time',
    ]);
  });
});
