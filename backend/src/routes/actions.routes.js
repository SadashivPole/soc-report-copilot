'use strict';
const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const svc = require('../services/actions.service');

const router = express.Router();
router.use(requireAuth);

const isUuidErr = (e) => String(e.message).includes('invalid input syntax');

// Summary counts (feeds the executive dashboard: open vs resolved findings).
router.get('/summary', async (req, res, next) => {
  try {
    res.json({ summary: await svc.countsByStatus(req.auth.tenantId) });
  } catch (e) {
    next(e);
  }
});

// List actions (optionally filtered by status). Any authenticated tenant member.
router.get('/', async (req, res, next) => {
  try {
    const actions = await svc.listActions(req.auth.tenantId, { status: req.query.status });
    res.json({ actions });
  } catch (e) {
    next(e);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    const action = await svc.getAction(req.auth.tenantId, req.params.id);
    if (!action) return res.status(404).json({ error: 'Action not found' });
    res.json({ action });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Action not found' });
    next(e);
  }
});

// Create a manual action (Analyst+).
router.post('/', requireRole('analyst'), async (req, res, next) => {
  try {
    if (!req.body.finding || !req.body.recommended_action) {
      return res.status(400).json({ error: 'finding and recommended_action are required' });
    }
    const id = await svc.createAction(req.auth.tenantId, req.auth.userId, req.body);
    const action = await svc.getAction(req.auth.tenantId, id);
    res.status(201).json({ action });
  } catch (e) {
    next(e);
  }
});

// Update status / owner / priority / action text (Analyst+). Writes audit history.
router.patch('/:id', requireRole('analyst'), async (req, res, next) => {
  try {
    const action = await svc.updateAction(req.auth.tenantId, req.auth.userId, req.params.id, req.body);
    if (!action) return res.status(404).json({ error: 'Action not found' });
    res.json({ action });
  } catch (e) {
    if (e.statusCode === 400) return res.status(400).json({ error: e.message });
    if (isUuidErr(e)) return res.status(404).json({ error: 'Action not found' });
    next(e);
  }
});

// Delete an action (Admin only).
router.delete('/:id', requireRole('admin'), async (req, res, next) => {
  try {
    const deleted = await svc.deleteAction(req.auth.tenantId, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Action not found' });
    res.json({ deleted });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Action not found' });
    next(e);
  }
});

module.exports = router;
