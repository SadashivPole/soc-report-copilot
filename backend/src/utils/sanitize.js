'use strict';
const config = require('../config');

/**
 * Coerce an untrusted value to a bounded, single-line-ish string.
 * Removes control characters (defends the terminal/log & downstream renderers)
 * and truncates to a max length. Never evaluates or interprets the content.
 */
function safeString(value, maxLen = config.limits.maxFieldChars) {
  if (value === null || value === undefined) return null;
  let s;
  if (typeof value === 'string') s = value;
  else if (typeof value === 'number' || typeof value === 'boolean') s = String(value);
  else {
    try {
      s = JSON.stringify(value);
    } catch {
      s = String(value);
    }
  }
  // Strip ASCII control chars except normal whitespace (\t \n \r handled below).
  s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ');
  if (s.length > maxLen) s = s.slice(0, maxLen) + '…';
  return s;
}

/** Truncate long free-text fields such as full_log. */
function truncate(value, maxLen = config.limits.maxFullLogChars) {
  if (value === null || value === undefined) return null;
  const s = typeof value === 'string' ? value : String(value);
  const cleaned = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ');
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) + '…[truncated]' : cleaned;
}

/** HTML-escape (used only where we must emit markup; UI prefers textContent). */
function escapeHtml(value) {
  const s = safeString(value, 100000) || '';
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { safeString, truncate, escapeHtml };
