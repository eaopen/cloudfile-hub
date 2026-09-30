import Search from './search';

// Icons use Webpack's require.context, which is unavailable in Jest.
jest.mock('@/components/icon', () => ({
  __esModule: true,
  default: () => null,
}));
// This test exercises visited-item storage without loading editor renderers.
jest.mock('./details', () => () => null);

describe('Search visited results', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes all existing duplicates before adding the visited item', () => {
    const targetItem = { repo_id: 'repo-1', path: '/document.md', name: 'document.md' };
    const otherItem = { repo_id: 'repo-2', path: '/document.md', name: 'document.md' };
    localStorage.setItem('sfVisitedSearchItems', JSON.stringify([
      targetItem,
      otherItem,
      { ...targetItem, name: 'outdated-document.md' },
      targetItem,
    ]));
    const search = new Search({ onSearchedClick: jest.fn() });

    search.keepVisitedItem(targetItem, '');

    expect(JSON.parse(localStorage.getItem('sfVisitedSearchItems'))).toEqual([
      targetItem,
      otherItem,
    ]);
  });
});
