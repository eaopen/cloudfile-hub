import { normalizeNewFileNameInput, validateNewFileName } from '../new-file-name';

describe('new CloudFile names: trim create/rename input, never stored names', () => {
  test.each([
    [' 项目 ', '项目'],
    ['\u3000项目\u3000', '项目'],
    ['  项目  2026  ', '项目  2026'],
    [' 合同. ', '合同.'],
    ['  CON  ', 'CON'],
  ])('normalizes new input %s to %s before validation', (input, expected) => {
    expect(normalizeNewFileNameInput(input)).toBe(expected);
  });
  test('validates normalized names without rewriting percent sequences', () => {
    expect(validateNewFileName(normalizeNewFileNameInput(' 项目 ')).isValid).toBe(true);
    expect(validateNewFileName(normalizeNewFileNameInput(' CON ')).isValid).toBe(false);
    expect(normalizeNewFileNameInput(' 报价%2B ')).toBe('报价%2B');
  });
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
