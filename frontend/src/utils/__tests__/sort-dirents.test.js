import { Utils } from '@/utils/utils';

jest.mock('@/constants', () => ({ PRIVATE_FILE_TYPE: {} }));
jest.mock('@/cloudfile/features', () => ({ isEnabled: () => false }));
jest.mock('@/components/toast', () => ({ danger: jest.fn(), success: jest.fn(), warning: jest.fn() }));
jest.mock('@/utils/constants', () => ({
  gettext: (text) => text,
  mediaUrl: '',
  serviceURL: '',
  siteRoot: '',
  isPro: false,
  fileAuditEnabled: false,
  canGenerateShareLink: false,
  canGenerateUploadLink: false,
  shareLinkPasswordMinLength: 8,
  username: 'tester',
  folderPermEnabled: false,
  cloudFileLockEnabled: false,
  onlyofficeConverterExtensions: [],
  enableSeadoc: false,
  enableRepoSnapshotLabel: false,
  enableResetEncryptedRepoPassword: false,
  isEmailConfigured: false,
  isSystemStaff: false,
  enableOnlyoffice: false,
  onlyofficeEditFileExtension: [],
  enableOfficeWebApp: false,
  officeWebAppEditFileExtension: [],
  enableMultipleOfficeSuite: false,
  officeSuiteEditFileExtension: [],
  PRIVATE_FILE_TYPE: {},
}));

const file = (name, extra = {}) => ({ type: 'file', name, mtime: 100, size_original: 0, ...extra });
const dir = (name, extra = {}) => ({ type: 'dir', name, mtime: 100, ...extra });
const names = (items) => items.map((item) => item.name);

// Shared-folder items use a different shape: is_dir, folder_name / file_name,
// last_modified, size.
const sharedFile = (name, extra = {}) => ({ is_dir: false, file_name: name, last_modified: '2024-01-01T00:00:00Z', size: 0, ...extra });
const sharedDir = (name, extra = {}) => ({ is_dir: true, folder_name: name, last_modified: '2024-01-01T00:00:00Z', ...extra });
const sharedNames = (items) => items.map((item) => (item.is_dir ? item.folder_name : item.file_name));

describe('getSortExtension follows the Windows PathFindExtension rule', () => {
  test.each([
    ['archive.tar.gz', 'gz'],
    ['report.docx', 'docx'],
    ['.gitignore', 'gitignore'],
    ['a.gitignore', 'gitignore'],
    ['README', ''],
    ['x.', ''],
    ['README.TXT', 'txt'],
    ['', ''],
    ['photo.JPG', 'jpg'],
  ])('%s -> "%s"', (input, expected) => {
    expect(Utils.getSortExtension(input)).toBe(expected);
  });
});

describe('sortDirents with ext key', () => {
  test('puts directories first, extension-less files next, then by extension', () => {
    const items = [
      file('b.zip'),
      file('README'),
      dir('folder-z'),
      file('a.txt'),
      file('c.zip'),
      dir('folder-a'),
      file('.gitignore'),
    ];

    expect(names(Utils.sortDirents(items, 'ext', 'asc'))).toEqual([
      'folder-a', 'folder-z', 'README', '.gitignore', 'a.txt', 'b.zip', 'c.zip',
    ]);
  });

  test('descending order flips files but keeps directories in front', () => {
    const items = [file('a.txt'), dir('folder'), file('b.zip')];

    expect(names(Utils.sortDirents(items, 'ext', 'desc'))).toEqual(['folder', 'b.zip', 'a.txt']);
  });

  test('groups a multi-dot name by its last segment', () => {
    const items = [file('z.tar.gz'), file('a.txt'), file('m.gz')];

    // 'z.tar.gz' keys on 'gz', so it sorts next to 'm.gz' rather than under 't'.
    expect(names(Utils.sortDirents(items, 'ext', 'asc'))).toEqual(['m.gz', 'z.tar.gz', 'a.txt']);
  });
});

describe('sortDirents is a total order', () => {
  const tied = [
    file('c.pdf', { mtime: 500, size_original: 10 }),
    file('a.pdf', { mtime: 500, size_original: 10 }),
    file('b.pdf', { mtime: 500, size_original: 10 }),
    dir('folder-b'),
    dir('folder-a'),
  ];

  test.each([
    [tied],
    [[...tied].reverse()],
    [[tied[2], tied[0], tied[4], tied[1], tied[3]]],
  ])('equal primary keys fall back to name regardless of input order', (input) => {
    expect(names(Utils.sortDirents([...input], 'time', 'asc'))).toEqual([
      'folder-a', 'folder-b', 'a.pdf', 'b.pdf', 'c.pdf',
    ]);
    expect(names(Utils.sortDirents([...input], 'size', 'asc'))).toEqual([
      'folder-a', 'folder-b', 'a.pdf', 'b.pdf', 'c.pdf',
    ]);
  });

  test('descending order is the exact reverse of ascending within files', () => {
    const asc = names(Utils.sortDirents([...tied], 'size', 'asc')).filter((n) => n.endsWith('.pdf'));
    const desc = names(Utils.sortDirents([...tied], 'size', 'desc')).filter((n) => n.endsWith('.pdf'));

    expect(desc).toEqual([...asc].reverse());
  });
});

describe('sortDirents with time and size keys', () => {
  test('orders by mtime and breaks ties by name', () => {
    const items = [file('b.txt', { mtime: 200 }), file('a.txt', { mtime: 200 }), file('c.txt', { mtime: 100 })];

    expect(names(Utils.sortDirents(items, 'time', 'asc'))).toEqual(['c.txt', 'a.txt', 'b.txt']);
  });

  test('orders by raw byte count, not the formatted size string', () => {
    const items = [
      file('big.txt', { size_original: 2048 }),
      file('small.txt', { size_original: 9 }),
      dir('folder'),
    ];

    expect(names(Utils.sortDirents(items, 'size', 'asc'))).toEqual(['folder', 'small.txt', 'big.txt']);
  });

  test('unknown sort key degrades to name order instead of throwing', () => {
    const items = [file('b.txt'), file('a.txt')];

    expect(names(Utils.sortDirents(items, 'something-else', 'asc'))).toEqual(['a.txt', 'b.txt']);
  });
});

describe('sortDirentsInSharedDir matches the library listing behaviour', () => {
  test('orders by extension with directories first', () => {
    const items = [
      sharedFile('b.zip'),
      sharedFile('README'),
      sharedDir('folder-z'),
      sharedFile('a.txt'),
      sharedDir('folder-a'),
    ];

    expect(sharedNames(Utils.sortDirentsInSharedDir(items, 'ext', 'asc'))).toEqual([
      'folder-a', 'folder-z', 'README', 'a.txt', 'b.zip',
    ]);
  });

  test('equal timestamps fall back to name, not input order', () => {
    const base = { last_modified: '2024-05-05T00:00:00Z' };
    const items = [
      sharedFile('c.txt', base),
      sharedDir('folder-b', base),
      sharedFile('a.txt', base),
      sharedDir('folder-a', base),
      sharedFile('b.txt', base),
    ];

    expect(sharedNames(Utils.sortDirentsInSharedDir(items, 'time', 'asc'))).toEqual([
      'folder-a', 'folder-b', 'a.txt', 'b.txt', 'c.txt',
    ]);
  });

  test('descending order flips files but keeps directories first', () => {
    const items = [sharedFile('a.txt'), sharedDir('folder'), sharedFile('b.zip')];

    expect(sharedNames(Utils.sortDirentsInSharedDir(items, 'ext', 'desc'))).toEqual(['folder', 'b.zip', 'a.txt']);
  });

  test('compares raw size numbers', () => {
    const items = [sharedFile('big.txt', { size: 2048 }), sharedFile('small.txt', { size: 9 }), sharedDir('folder')];

    expect(sharedNames(Utils.sortDirentsInSharedDir(items, 'size', 'asc'))).toEqual(['folder', 'small.txt', 'big.txt']);
  });
});

describe('Chinese-friendly natural name sorting', () => {
  const ZHANG = '张三.txt';
  const LI = '李四.txt';

  test('preserves the existing zh-Hans-CN ordering in directory lists', () => {
    expect(names(Utils.sortDirents([file(ZHANG), file(LI)], 'name', 'asc'))).toEqual([LI, ZHANG]);
    expect(sharedNames(Utils.sortDirentsInSharedDir([sharedFile(ZHANG), sharedFile(LI)], 'name', 'asc'))).toEqual([LI, ZHANG]);
    expect(Utils.compareTwoWord(ZHANG, LI)).toBeGreaterThan(0);
  });

  test('sorts dotted section numbers as natural numeric segments (not decimals)', () => {
    const input = ['1.12', '1.2', '1.11', '1.1'].map((name) => file(name));
    expect(names(Utils.sortDirents([...input], 'name', 'asc'))).toEqual(['1.1', '1.2', '1.11', '1.12']);
    expect(names(Utils.sortDirents([...input], 'name', 'desc'))).toEqual(['1.12', '1.11', '1.2', '1.1']);
    const shared = input.map(({ name }) => sharedFile(name));
    expect(sharedNames(Utils.sortDirentsInSharedDir(shared, 'name', 'asc'))).toEqual(['1.1', '1.2', '1.11', '1.12']);
  });

  test('breaks natural numeric ties by raw name for repeatable ordering', () => {
    const a = file('file1.txt');
    const b = file('file01.txt');
    expect(Utils.compareTwoWord(a.name, b.name)).toBe(0);
    expect(names(Utils.sortDirents([a, b], 'name', 'asc'))).toEqual(['file01.txt', 'file1.txt']);
    expect(names(Utils.sortDirents([b, a], 'name', 'asc'))).toEqual(['file01.txt', 'file1.txt']);
    expect(names(Utils.sortDirents([a, b], 'time', 'asc'))).toEqual(['file01.txt', 'file1.txt']);
    expect(names(Utils.sortDirents([a, b], 'name', 'desc'))).toEqual(['file1.txt', 'file01.txt']);
    expect(Utils.compareDirentName(a.name, a.name)).toBe(0);
  });
});
