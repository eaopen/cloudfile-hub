/**
 * Policy for files/folders newly created or renamed in the CloudFile web UI.
 * Do NOT use on historical paths, imported data, copy/move source names or
 * migration APIs. Only user-entered create/rename input is trimmed;
 * this validator rejects other invalid characters instead of replacing them.
 */
import { gettext } from '@/utils/constants';

const WINDOWS_FORBIDDEN = /[<>:"/\\|?*]/;
// Explicit C0/C1 and format controls are disallowed for newly created names.
// eslint-disable-next-line no-control-regex, no-misleading-character-class
const NONDISPLAY_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u034f\u180e\u200b\u200c\u2060\u202a-\u202e\u2066-\u2069\ufeff]/u;
const WINDOWS_DEVICE = /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i;

// Use at the create/rename form boundary only. Existing paths never get trimmed.
export const normalizeNewFileNameInput = (name) => typeof name === 'string' ? name.trim() : '';

const reject = (message) => ({ isValid: false, errMessage: gettext(message) });

export const validateNewFileName = (name) => {
  if (typeof name !== 'string' || !name.trim()) return reject('Name is required');
  if (name !== name.trim()) return reject('Name cannot start or end with whitespace');
  if (name.endsWith('.')) return reject('Name cannot end with a dot');
  if (WINDOWS_FORBIDDEN.test(name)) return reject('Name contains characters not supported by Windows');
  if (NONDISPLAY_CONTROLS.test(name)) return reject('Name cannot contain control or invisible formatting characters');
  if (WINDOWS_DEVICE.test(name)) return reject('Name is a reserved Windows device name');
  // Backtick and existing filename policy are still checked by validateName.
  return { isValid: true, errMessage: '' };
};
