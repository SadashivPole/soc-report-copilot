'use strict';
const fs = require('fs');
const pathmod = require('path');
const express = require('express');
const multer = require('multer');
const config = require('../config');
const { requireAuth, requireRole } = require('../middleware/auth');
const { query, withTransaction } = require('../db/pool');
const { getConnector } = require('../services/parser');

const router = express.Router();
router.use(requireAuth);

// In-memory upload (no temp files on disk); size-capped.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.limits.maxUploadBytes, files: 1 },
});

function detectFormat(filename, buffer) {
  const name = (filename || '').toLowerCase();
  if (name.endsWith('.csv')) return 'csv';
  if (name.endsWith('.json') || name.endsWith('.ndjson') || name.endsWith('.log')) return 'json';
  // Sniff content: starts with { or [ → json, else csv.
  const head = buffer.slice(0, 64).toString('utf8').trimStart();
  return head.startsWith('{') || head.startsWith('[') ? 'json' : 'csv';
}

router.post('/', requireRole('analyst'), upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name: file)' });
    // Untrusted-input validation: reject empty files and obviously wrong types.
    if (req.file.size === 0) return res.status(400).json({ error: 'Uploaded file is empty' });
    const okName = /\.(json|ndjson|log|csv)$/i.test(req.file.originalname || '');
    if (!okName) return res.status(400).json({ error: 'Only .json, .ndjson, .log or .csv files are accepted' });
    const sourceType = (req.body.sourceType || 'wazuh').toLowerCase();
    let connector;
    try {
      connector = getConnector(sourceType);
    } catch {
      return res.status(400).json({ error: `Unsupported sourceType: ${sourceType}` });
    }

    const format = detectFormat(req.file.originalname, req.file.buffer);

    // Parse BEFORE opening a transaction so parse failures don't leave rows.
    let parsed;
    try {
      parsed = connector.parse(req.file.buffer, format);
    } catch (e) {
      // Record the failed attempt for history, then return 400.
      await query(
        `INSERT INTO uploads(tenant_id, user_id, filename, format, source_type, status, error)
         VALUES($1,$2,$3,$4,$5,'failed',$6)`,
        [req.auth.tenantId, req.auth.userId, String(req.file.originalname).slice(0, 255), format, sourceType, e.message.slice(0, 500)]
      );
      return res.status(400).json({ error: `Failed to parse ${format.toUpperCase()}: ${e.message}` });
    }

    const result = await withTransaction(async (client) => {
      const up = await client.query(
        `INSERT INTO uploads(tenant_id, user_id, filename, format, source_type, event_count, status)
         VALUES($1,$2,$3,$4,$5,$6,'parsed') RETURNING *`,
        [
          req.auth.tenantId,
          req.auth.userId,
          String(req.file.originalname).slice(0, 255),
          format,
          sourceType,
          parsed.events.length,
        ]
      );
      const uploadRow = up.rows[0];

      // Bulk insert events in batches (parameterized — no injection surface).
      const cols = [
        'tenant_id', 'upload_id', 'event_id', 'ts', 'rule_id', 'rule_description',
        'rule_level', 'severity', 'groups', 'mitre', 'agent_name', 'agent_ip',
        'src_ip', 'dst_ip', 'src_user', 'dst_user', 'full_log', 'raw',
      ];
      const BATCH = 500;
      for (let i = 0; i < parsed.events.length; i += BATCH) {
        const slice = parsed.events.slice(i, i + BATCH);
        const values = [];
        const placeholders = slice
          .map((ev, j) => {
            const base = j * cols.length;
            values.push(
              req.auth.tenantId,
              uploadRow.id,
              ev.event_id,
              ev.timestamp,
              ev.rule_id,
              ev.rule_description,
              ev.rule_level,
              ev.severity,
              JSON.stringify(ev.groups || []),
              JSON.stringify({ ids: ev.mitre_ids || [], tactics: ev.mitre_tactics || [], techniques: ev.mitre_techniques || [] }),
              ev.agent_name,
              ev.agent_ip,
              ev.src_ip,
              ev.dst_ip,
              ev.src_user,
              ev.dst_user,
              ev.full_log,
              JSON.stringify(ev.raw || {})
            );
            return `(${cols.map((_, k) => `$${base + k + 1}`).join(',')})`;
          })
          .join(',');
        await client.query(`INSERT INTO events(${cols.join(',')}) VALUES ${placeholders}`, values);
      }
      return uploadRow;
    });

    res.status(201).json({ upload: result, truncated: parsed.truncated, event_count: parsed.events.length });
  } catch (e) {
    next(e);
  }
});

// Onboarding helper: ingest the bundled synthetic Wazuh sample for this tenant.
router.post('/sample', requireRole('analyst'), async (req, res, next) => {
  try {
    const samplePath = pathmod.join(__dirname, '..', '..', 'seed', 'wazuh_sample.json');
    if (!fs.existsSync(samplePath)) return res.status(404).json({ error: 'Sample dataset not available. Run the seed generator.' });
    const buf = fs.readFileSync(samplePath);
    const parsed = getConnector('wazuh').parse(buf, 'json');
    const result = await withTransaction(async (client) => {
      const up = await client.query(
        `INSERT INTO uploads(tenant_id, user_id, filename, format, source_type, event_count, status)
         VALUES($1,$2,'wazuh_sample.json','json','wazuh',$3,'parsed') RETURNING *`,
        [req.auth.tenantId, req.auth.userId, parsed.events.length]
      );
      const uploadRow = up.rows[0];
      const cols = ['tenant_id','upload_id','event_id','ts','rule_id','rule_description','rule_level','severity','groups','mitre','agent_name','agent_ip','src_ip','dst_ip','src_user','dst_user','full_log','raw'];
      const BATCH = 500;
      for (let i = 0; i < parsed.events.length; i += BATCH) {
        const slice = parsed.events.slice(i, i + BATCH);
        const values = [];
        const placeholders = slice.map((ev, j) => {
          const base = j * cols.length;
          values.push(req.auth.tenantId, uploadRow.id, ev.event_id, ev.timestamp, ev.rule_id, ev.rule_description, ev.rule_level, ev.severity,
            JSON.stringify(ev.groups || []), JSON.stringify({ ids: ev.mitre_ids || [], tactics: ev.mitre_tactics || [], techniques: ev.mitre_techniques || [] }),
            ev.agent_name, ev.agent_ip, ev.src_ip, ev.dst_ip, ev.src_user, ev.dst_user, ev.full_log, JSON.stringify(ev.raw || {}));
          return `(${cols.map((_, k) => `$${base + k + 1}`).join(',')})`;
        }).join(',');
        await client.query(`INSERT INTO events(${cols.join(',')}) VALUES ${placeholders}`, values);
      }
      return uploadRow;
    });
    res.status(201).json({ upload: result, event_count: parsed.events.length, sample: true });
  } catch (e) { next(e); }
});

router.get('/', async (req, res, next) => {
  try {
    const r = await query(
      `SELECT id, filename, format, source_type, event_count, status, error, uploaded_at
         FROM uploads WHERE tenant_id=$1 ORDER BY uploaded_at DESC LIMIT 200`,
      [req.auth.tenantId]
    );
    res.json({ uploads: r.rows });
  } catch (e) {
    next(e);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    // Tenant-scoped lookup: another tenant's id simply returns 404.
    const r = await query(
      `SELECT id, filename, format, source_type, event_count, status, error, uploaded_at
         FROM uploads WHERE id=$1 AND tenant_id=$2`,
      [req.params.id, req.auth.tenantId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Upload not found' });
    res.json({ upload: r.rows[0] });
  } catch (e) {
    // invalid uuid → treat as not found
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Upload not found' });
    next(e);
  }
});

// Delete an upload and ALL derived data (events + reports cascade via FK). Analyst+.
router.delete('/:id', requireRole('analyst'), async (req, res, next) => {
  try {
    const r = await query('DELETE FROM uploads WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, req.auth.tenantId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Upload not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (e) {
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Upload not found' });
    next(e);
  }
});

module.exports = router;
