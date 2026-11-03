import { validateNewFileName } from '../new-file-name';

describe('new CloudFile names: strict at write time, no normalization', () => {
  test.each(['项目 2026', '项目  2026', '报价+核对&预算#1.xlsx',
    '报价%2B核对.xlsx', '合同｜A', 'a..b', 'e\u0301.txt', 'é.txt', '😊.txt'])(
    'allows the exact visible name %s', (name) => {
      expect(validateNewFileName(name).isValid).toBe(true);
    }
  );

  test.each(['', ' ', ' 项目', '项目 ', '项目\u3000', '项目.', '.', '..',
    'CON', 'con.txt', 'COM¹.txt', 'LPT1.doc', 'file|name', 'file\\name', 'file/name',
    'file\nname', 'a\u200Bb', 'a\u202Eb'])(
    'rejects a new invalid name %s', (name) => {
      expect(validateNewFileName(name).isValid).toBe(false);
    }
  );
});
