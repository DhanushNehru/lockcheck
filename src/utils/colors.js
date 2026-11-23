/**
 * ANSI color utilities for terminal output.
 * Zero dependencies — raw escape codes.
 * Respects NO_COLOR env var and CI environments.
 */

const isColorSupported = !process.env.NO_COLOR && (
  process.stdout.isTTY || process.env.FORCE_COLOR === '1'
);

function wrap(code, resetCode) {
  if (!isColorSupported) return (str) => str;
  return (str) => `\x1b[${code}m${str}\x1b[${resetCode}m`;
}

export const bold = wrap('1', '22');
export const dim = wrap('2', '22');
export const italic = wrap('3', '23');
export const underline = wrap('4', '24');
export const red = wrap('31', '39');
export const green = wrap('32', '39');
export const yellow = wrap('33', '39');
export const blue = wrap('34', '39');
export const magenta = wrap('35', '39');
export const cyan = wrap('36', '39');
export const white = wrap('37', '39');
export const gray = wrap('90', '39');

// Bright variants
export const brightRed = wrap('91', '39');
export const brightGreen = wrap('92', '39');
export const brightYellow = wrap('93', '39');
export const brightCyan = wrap('96', '39');

// Background colors
export const bgRed = wrap('41', '49');
export const bgGreen = wrap('42', '49');
export const bgYellow = wrap('43', '49');

// Combined styles
export const error = (str) => bold(red(str));
export const warning = (str) => bold(yellow(str));
export const success = (str) => bold(green(str));
export const info = (str) => bold(cyan(str));

// Icons
export const ICONS = {
  check: isColorSupported ? '✅' : '[OK]',
  warning: isColorSupported ? '⚠️ ' : '[WARN]',
  timer: isColorSupported ? '⏱️' : '[TIME]',
  critical: isColorSupported ? '🔴' : '[CRIT]',
  lock: isColorSupported ? '🔒' : '[LOCK]',
  package: isColorSupported ? '📦' : '[PKG]',
  search: isColorSupported ? '🔍' : '[SCAN]',
  shield: isColorSupported ? '🛡️ ' : '[SAFE]',
  skull: isColorSupported ? '💀' : '[DANGER]',
  new: isColorSupported ? '🆕' : '[NEW]',
  arrow: isColorSupported ? '→' : '->',
  bullet: isColorSupported ? '•' : '-',
};
