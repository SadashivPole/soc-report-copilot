'use strict';
const jwt = require('jsonwebtoken');
const config = require('../config');

// Role hierarchy for RBAC. Higher number = more capability.
const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

/** Legacy 'owner' accounts are treated as 'admin'. */
function normalizeRole(role) {
  if (role === 'owner') return 'admin';
  return ROLE_RANK[role] ? role : 'viewer';
}

/**
 * Verifies the Bearer JWT and injects req.auth = { userId, tenantId, role }.
 * The tenantId used for every downstream query comes ONLY from the verified
 * token — never from request body/query — which is the core of tenant isolation.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  try {
    const payload = jwt.verify(match[1], config.jwtSecret);
    if (!payload.userId || !payload.tenantId) throw new Error('bad payload');
    req.auth = {
      userId: payload.userId,
      tenantId: payload.tenantId,
      role: normalizeRole(payload.role),
    };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * requireRole('analyst') → allows analyst and any higher role (admin).
 * requireRole('admin')   → admin only.
 * Must be used after requireAuth.
 */
function requireRole(minRole) {
  const min = ROLE_RANK[minRole] || 99;
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ error: 'Authentication required' });
    if ((ROLE_RANK[req.auth.role] || 0) < min) {
      return res.status(403).json({ error: `Requires ${minRole} role or higher` });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, normalizeRole, ROLE_RANK };
