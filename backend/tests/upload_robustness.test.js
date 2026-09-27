'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

test('empty file is rejected with 400', async () => {
  const A = await h.signup('rob1@t.com');
  const r = await h.uploadRaw(A.token, '', 'empty.json');
  assert.equal(r.status, 400);
});

test('malformed JSON (not JSON or NDJSON) is rejected with 400 and logged as failed', async () => {
  const A = await h.signup('rob2@t.com');
  const r = await h.uploadRaw(A.token, '{ this is : not valid, json ]', 'bad.json');
  assert.equal(r.status, 400);
  // The failed attempt is recorded for history (status='failed').
  const failed = await h.pool.query("SELECT status FROM uploads WHERE tenant_id=$1 AND status='failed'", [A.tenant.id]);
  assert.ok(failed.rowCount >= 1);
});

test('NDJSON with some malformed lines ingests the valid records only', async () => {
  const A = await h.signup('rob3@t.com');
  const good1 = JSON.stringify({ id: 'g1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '1', level: 5, description: 'ok' }, agent: { name: 'a' } });
  const good2 = JSON.stringify({ id: 'g2', timestamp: '2026-09-20T10:01:00Z', rule: { id: '2', level: 5, description: 'ok2' }, agent: { name: 'b' } });
  const content = good1 + '\n{ broken line \n' + good2;
  const r = await h.uploadRaw(A.token, content, 'mixed.ndjson');
  assert.equal(r.status, 201);
  assert.equal(r.data.event_count, 2, 'only the 2 valid records ingested');
});

test('missing fields are tolerated: severity defaults, event_id synthesized', async () => {
  const A = await h.signup('rob4@t.com');
  // No id, no level, no agent — should not crash; defaults applied.
  const alerts = [{ rule: { description: 'no level, no id' } }, { foo: 'bar' }];
  const r = await h.uploadJson(A.token, alerts, 'sparse.json');
  assert.equal(r.status, 201);
  assert.equal(r.data.event_count, 2);
  const evs = await h.pool.query('SELECT event_id, severity FROM events WHERE tenant_id=$1 ORDER BY event_id', [A.tenant.id]);
  assert.ok(evs.rows.every((e) => e.event_id && e.severity), 'every event has an id + severity');
});

test('duplicate event IDs are all retained (counts are honest, not deduped away)', async () => {
  const A = await h.signup('rob5@t.com');
  const dup = [];
  for (let i = 0; i < 6; i++) dup.push({ id: 'same-id', timestamp: '2026-09-20T10:00:00Z', rule: { id: '5', level: 8, description: 'dup' }, agent: { name: 'a' } });
  const r = await h.uploadJson(A.token, dup, 'dups.json');
  assert.equal(r.status, 201);
  assert.equal(r.data.event_count, 6);
  const dash = await h.req('GET', '/api/dashboard?uploadId=' + r.data.upload.id, { token: A.token });
  assert.equal(dash.data.totals.total, 6);
});

test('empty (zero-alert) file is rejected cleanly with 400 (no partial state)', async () => {
  // By design the parser refuses a payload that contains no alerts, so no empty
  // upload/report is ever created. This is verified end-to-end here.
  const A = await h.signup('rob6@t.com');
  const r = await h.uploadJson(A.token, [], 'none.json');
  assert.equal(r.status, 400);
  const parsed = await h.pool.query("SELECT count(*)::int c FROM uploads WHERE tenant_id=$1 AND status='parsed'", [A.tenant.id]);
  assert.equal(parsed.rows[0].c, 0, 'no parsed upload row left behind');
});

test('a report over a minimal dataset still renders both PDF modes', async () => {
  const A = await h.signup('rob6b@t.com');
  const minimal = [{ id: 'm1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '1', level: 3, description: 'benign' }, agent: { name: 'a' } }];
  const up = await h.uploadJson(A.token, minimal, 'min.json');
  assert.equal(up.status, 201);
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  assert.equal(rep.status, 201);
  assert.equal(rep.data.report.data.findings.length, 0);
  assert.match(rep.data.report.data.mitre_section.note, /Not enough evidence/);
  for (const mode of ['executive', 'analyst']) {
    const pdf = await h.req('GET', `/api/reports/${rep.data.report.id}/pdf?mode=${mode}`, { token: A.token, raw: true });
    assert.equal(pdf.status, 200);
  }
});

test('large upload (6000 events) is ingested and dashboards aggregate correctly', async () => {
  const A = await h.signup('rob7@t.com');
  const big = [];
  for (let i = 0; i < 6000; i++) {
    big.push({ id: 'e' + i, timestamp: '2026-09-2' + (i % 5) + 'T10:00:00Z', rule: { id: '5712', level: 8, description: 'auth fail', groups: ['sshd'] }, agent: { name: 'h' + (i % 10) }, data: { srcip: '10.0.0.' + (i % 50) } });
  }
  const r = await h.uploadJson(A.token, big, 'big.json');
  assert.equal(r.status, 201);
  assert.equal(r.data.event_count, 6000);
  const dash = await h.req('GET', '/api/dashboard?uploadId=' + r.data.upload.id, { token: A.token });
  assert.equal(dash.data.totals.total, 6000);
});

test('malicious log content is stored/rendered as inert text (no execution path)', async () => {
  const A = await h.signup('rob8@t.com');
  const xss = '<script>alert(1)</script>';
  const sqli = "'; DROP TABLE events;--";
  const alerts = [];
  for (let i = 0; i < 5; i++) {
    alerts.push({
      id: 'mal-' + i,
      timestamp: '2026-09-20T10:00:00Z',
      rule: { id: '5712', level: 10, description: 'sshd: brute force ' + xss, groups: ['sshd', 'brute_force'], mitre: { id: ['T1110'] } },
      agent: { name: 'host' },
      data: { srcip: '203.0.113.44', dstuser: sqli },
      full_log: xss + ' ' + sqli,
    });
  }
  const up = await h.uploadJson(A.token, alerts, 'evil.json');
  assert.equal(up.status, 201);
  // events table intact (no SQL injection executed)
  const cnt = await h.pool.query('SELECT count(*)::int c FROM events WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(cnt.rows[0].c, 5);
  // report generates and the raw content is preserved verbatim as data (not executed/interpreted)
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  assert.equal(rep.status, 201);
  const appx = rep.data.report.data.evidence_appendix;
  assert.ok(appx.some((e) => (e.evidence || '').includes('script')), 'raw content retained as text');
  // PDF renders fine with malicious content present
  const pdf = await h.req('GET', '/api/reports/' + rep.data.report.id + '/pdf?mode=analyst', { token: A.token, raw: true });
  assert.equal(pdf.status, 200);
  const buf = Buffer.from(await pdf.arrayBuffer());
  assert.equal(buf.slice(0, 5).toString(), '%PDF-');
});
