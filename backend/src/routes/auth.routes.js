'use strict';
const express = require('express');
const rateLimit = require('express-rate-limit');
const authService = require('../services/auth.service');
const { requireAuth } = require('../middleware/auth');
const { query } = require('../db/pool');

const router = express.Router();

// Throttle credential endpoints to blunt brute-force / enumeration.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

router.post('/signup', authLimiter, async (req, res, next) => {
  try {
    const result = await authService.signup(req.body || {});
    res.status(201).json(result);
  } catch (e) {
    next(e);
  }
});

router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const result = await authService.login(req.body || {});
    res.json(result);
  } catch (e) {
    next(e);
  }
});

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const r = await query(
      `SELECT u.id, u.email, u.role, t.id AS tenant_id, t.name AS tenant_name
         FROM users u JOIN tenants t ON t.id = u.tenant_id
        WHERE u.id = $1 AND u.tenant_id = $2`,
      [req.auth.userId, req.auth.tenantId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (e) {
    next(e);
  }
});

module.exports = router;
