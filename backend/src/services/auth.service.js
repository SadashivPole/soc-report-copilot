'use strict';
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { query, withTransaction } = require('../db/pool');

function signToken(user) {
  return jwt.sign(
    { userId: user.id, tenantId: user.tenant_id, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

/**
 * Sign up provisions a NEW tenant and its owner user in one transaction, giving
 * each account its own isolated tenant boundary.
 */
async function signup({ email, password, tenantName }) {
  if (!isValidEmail(email)) throw httpError(400, 'A valid email is required');
  if (typeof password !== 'string' || password.length < 8)
    throw httpError(400, 'Password must be at least 8 characters');

  const normEmail = email.toLowerCase().trim();
  const existing = await query('SELECT 1 FROM users WHERE email=$1', [normEmail]);
  if (existing.rowCount) throw httpError(409, 'Email already registered');

  const passwordHash = await bcrypt.hash(password, 10);

  const orgName = (tenantName && String(tenantName).slice(0, 120)) || `${normEmail.split('@')[0]}'s org`;

  return withTransaction(async (client) => {
    const t = await client.query(
      'INSERT INTO tenants(name, company_name, plan) VALUES($1,$1,$2) RETURNING *',
      [orgName, config.defaultPlan]
    );
    const tenant = t.rows[0];
    // The first user of a tenant is its admin.
    const u = await client.query(
      `INSERT INTO users(tenant_id, email, password_hash, role)
       VALUES($1,$2,$3,'admin') RETURNING id, tenant_id, email, role, created_at`,
      [tenant.id, normEmail, passwordHash]
    );
    const user = u.rows[0];
    return { token: signToken(user), user, tenant: { id: tenant.id, name: tenant.name, plan: tenant.plan } };
  });
}

async function login({ email, password }) {
  if (!isValidEmail(email) || typeof password !== 'string')
    throw httpError(400, 'Email and password are required');
  const normEmail = email.toLowerCase().trim();
  const r = await query(
    'SELECT u.*, t.name AS tenant_name FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE email=$1',
    [normEmail]
  );
  const user = r.rows[0];
  // Constant-ish behavior: always run a compare to reduce user-enumeration timing.
  const ok = user ? await bcrypt.compare(password, user.password_hash) : await bcrypt.compare(password, '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinv');
  if (!user || !ok) throw httpError(401, 'Invalid credentials');
  return {
    token: signToken(user),
    user: { id: user.id, tenant_id: user.tenant_id, email: user.email, role: user.role },
    tenant: { id: user.tenant_id, name: user.tenant_name },
  };
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8)
    throw httpError(400, 'Password must be at least 8 characters');
  return bcrypt.hash(password, 10);
}

module.exports = { signup, login, signToken, httpError, isValidEmail, hashPassword };
