'use strict';

/**
 * Build a tenant-scoped SQL WHERE clause with optional upload and time-window
 * narrowing. tenant_id is ALWAYS the first bound parameter (tenant isolation is
 * never optional). The time window is half-open: [start, end).
 *
 * Passing uploadId = null with a window produces a cross-upload, window-scoped
 * query (used by scheduled weekly reports, which must cover a defined period
 * rather than an entire historical upload).
 *
 * @param {string} tenantId
 * @param {string|null} uploadId
 * @param {{start?: Date|string, end?: Date|string}|null} window
 * @returns {{ where: string, params: any[] }}
 */
function buildScope(tenantId, uploadId, window) {
  const params = [tenantId];
  let where = 'tenant_id = $1';
  if (uploadId) {
    params.push(uploadId);
    where += ` AND upload_id = $${params.length}`;
  }
  if (window && window.start) {
    params.push(window.start);
    where += ` AND ts >= $${params.length}`;
  }
  if (window && window.end) {
    params.push(window.end);
    where += ` AND ts < $${params.length}`;
  }
  return { where, params };
}

module.exports = { buildScope };
