'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');
const { generate } = require('../seed/generate');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

// Build alerts with a strong recurring brute-force pattern from one IP so the
// engine has real evidence to cite.
function alertsWithPattern() {
  const list = [];
  for (let i = 0; i < 12; i++) {
    list.push({
      id: 'bf-' + i,
      timestamp: '2026-09-2' + (i % 5) + 'T10:0' + (i % 6) + ':00Z',
      rule: { id: '5712', level: 10, description: 'sshd: Multiple authentication failures', groups: ['sshd', 'authentication_failures', 'brute_force'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
      agent: { name: 'bastion01' },
      data: { srcip: '203.0.113.77', dstuser: 'root' },
      full_log: 'Failed password for root from 203.0.113.77',
    });
  }
  // add benign noise (low severity, high volume) for false-positive candidate
  for (let i = 0; i < 30; i++) {
    list.push({
      id: 'noise-' + i,
      timestamp: '2026-09-2' + (i % 5) + 'T11:00:00Z',
      rule: { id: '533', level: 3, description: 'Netstat listened ports status changed', groups: ['ossec', 'monitor'] },
      agent: { name: 'app01' },
      full_log: 'Listened ports status changed',
    });
  }
  return list;
}

test('report generation cites evidence for every finding', async () => {
  const A = await h.signup('rep@t.com');
  const up = await h.uploadJson(A.token, alertsWithPattern());
  const uploadId = up.data.upload.id;

  const r = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId, title: 'Weekly SOC Report' } });
  assert.equal(r.status, 201);
  const d = r.data.report.data;

  // dashboard numbers
  assert.equal(d.dashboard.totals.total, 42);

  // AI label + disclaimer present
  assert.match(d.ai_analysis.label, /AI-assisted analysis \(evidence-bound\)/);
  assert.ok(d.ai_analysis.disclaimer.length > 0);

  // recurring pattern found and cites event ids
  assert.ok(d.ai_analysis.recurring_patterns.length >= 1);
  for (const p of d.ai_analysis.recurring_patterns) {
    assert.ok(Array.isArray(p.evidence_event_ids) && p.evidence_event_ids.length > 0, 'pattern must cite evidence');
  }

  // false-positive candidate found (the netstat noise) and cites evidence
  assert.ok(d.ai_analysis.false_positive_candidates.length >= 1);
  for (const fp of d.ai_analysis.false_positive_candidates) {
    assert.ok(fp.evidence_event_ids.length > 0);
    assert.match(fp.reason, /NOT a determination/);
  }
});

test('MITRE mapping is evidence-gated', async () => {
  const A = await h.signup('mit@t.com');

  // Case 1: alerts WITH mitre metadata → mapping present, cites events
  const up1 = await h.uploadJson(A.token, alertsWithPattern());
  const r1 = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up1.data.upload.id } });
  const m1 = r1.data.report.data.mitre_attack;
  assert.ok(m1.mappings.length >= 1);
  assert.ok(m1.mappings.some((x) => x.technique_id === 'T1110'));
  for (const mp of m1.mappings) assert.ok(mp.evidence_event_ids.length > 0);

  // Case 2: alerts with NO mitre metadata and no mappable groups → "Not enough evidence."
  const plain = [{ id: 'p1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '999', level: 3, description: 'benign info', groups: ['ossec'] }, agent: { name: 'x' }, full_log: 'ok' }];
  const up2 = await h.uploadJson(A.token, plain);
  const r2 = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up2.data.upload.id } });
  const m2 = r2.data.report.data.mitre_attack;
  assert.equal(m2.mappings.length, 0);
  assert.match(m2.note, /Not enough evidence/);
});

test('report is downloadable as a valid PDF', async () => {
  const A = await h.signup('pdf@t.com');
  const up = await h.uploadJson(A.token, alertsWithPattern());
  const r = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  const reportId = r.data.report.id;

  const res = await h.req('GET', '/api/reports/' + reportId + '/pdf', { token: A.token, raw: true });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/pdf');
  const buf = Buffer.from(await res.arrayBuffer());
  assert.ok(buf.length > 800, 'pdf should be non-trivial');
  assert.equal(buf.slice(0, 5).toString(), '%PDF-', 'valid PDF magic header');
});

test('seed generator produces well-formed alerts', () => {
  const alerts = generate(50);
  assert.equal(alerts.length, 50);
  assert.ok(alerts.every((a) => a.rule && a.rule.description));
  assert.ok(alerts.some((a) => a.rule.mitre)); // some carry ATT&CK metadata
});
