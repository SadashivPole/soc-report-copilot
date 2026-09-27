'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

// Correlated brute-force cluster (same src IP + rule, >=5) + recurring critical
// malware rule so the engine produces high-confidence, evidence-cited findings.
function richAlerts() {
  const list = [];
  for (let i = 0; i < 12; i++) {
    list.push({
      id: 'bf-' + i,
      timestamp: '2026-09-2' + (i % 5) + 'T10:0' + (i % 6) + ':00Z',
      rule: { id: '5712', level: 10, description: 'sshd: Multiple authentication failures (possible brute force)', groups: ['sshd', 'authentication_failures', 'brute_force'], mitre: { id: ['T1110'] } },
      agent: { name: 'bastion0' + (i % 3) },
      data: { srcip: '203.0.113.77', dstuser: 'root' },
      full_log: 'Failed password for root from 203.0.113.77',
    });
  }
  for (let i = 0; i < 6; i++) {
    list.push({
      id: 'mal-' + i,
      timestamp: '2026-09-2' + (i % 5) + 'T12:00:00Z',
      rule: { id: '87105', level: 13, description: 'Windows: Malware detected by Windows Defender', groups: ['windows', 'malware'] },
      agent: { name: 'app0' + (i % 2) },
      data: { dstuser: 'svc_backup' },
      full_log: 'Threat detected: Trojan:Win32/Test',
    });
  }
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

test('professional report has all 9 sections with evidence-cited findings', async () => {
  const A = await h.signup('pro@t.com');
  const up = await h.uploadJson(A.token, richAlerts());
  const r = await h.req('POST', '/api/reports', {
    token: A.token,
    body: { uploadId: up.data.upload.id, title: 'Weekly SOC Report', organization: 'Acme SOC', clientName: 'Globex' },
  });
  assert.equal(r.status, 201);
  const d = r.data.report.data;

  // meta / customization
  assert.equal(d.meta.title, 'Weekly SOC Report');
  assert.equal(d.meta.organization, 'Acme SOC');
  assert.equal(d.meta.client_name, 'Globex');
  assert.ok(d.meta.generated_at);
  assert.ok(d.meta.posture && d.meta.posture.label, 'posture label present');

  // §1 exec summary / kpis
  assert.equal(d.kpis.total, 48);
  assert.ok(d.executive_summary.headline.length > 0);

  // §2 posture: recurring vs new adds up to total
  assert.equal((d.kpis.recurring_alerts || 0) + (d.kpis.new_alerts || 0), d.kpis.total);

  // §4 findings — EVERY finding cites real event IDs (evidence traceability)
  assert.ok(d.findings.length >= 1, 'has findings');
  for (const f of d.findings) {
    assert.ok(f.title && f.severity && f.confidence, 'finding has core fields');
    assert.ok(Array.isArray(f.evidence.event_ids) && f.evidence.event_ids.length > 0, 'finding cites event IDs');
    assert.ok('first_seen' in f.evidence && 'last_seen' in f.evidence, 'finding has timestamps');
  }

  // §8 recommended actions labelled as AI-assisted (not fact), each evidence-bound
  assert.ok(d.recommended_actions.length >= 1);
  for (const a of d.recommended_actions) {
    assert.equal(a.label, 'AI-assisted recommendation');
    assert.ok(a.priority && a.owner && a.recommended_action);
    assert.ok(a.evidence.event_ids.length > 0);
  }

  // §9 evidence appendix — every row has an event_id + source
  assert.ok(d.evidence_appendix.length > 0);
  for (const e of d.evidence_appendix.slice(0, 10)) {
    assert.ok(e.event_id, 'appendix row has event_id');
    assert.equal(e.source, 'wazuh');
  }

  // integrity policy present
  assert.match(d.integrity.evidence_policy, /evidence/i);
});

test('executive and analyst PDFs both render as valid PDFs', async () => {
  const A = await h.signup('modes@t.com');
  const up = await h.uploadJson(A.token, richAlerts());
  const r = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  const id = r.data.report.id;

  for (const mode of ['executive', 'analyst']) {
    const res = await h.req('GET', `/api/reports/${id}/pdf?mode=${mode}`, { token: A.token, raw: true });
    assert.equal(res.status, 200, `${mode} pdf 200`);
    assert.equal(res.headers.get('content-type'), 'application/pdf');
    const buf = Buffer.from(await res.arrayBuffer());
    assert.equal(buf.slice(0, 5).toString(), '%PDF-', `${mode} valid PDF header`);
    assert.ok(buf.length > 2000, `${mode} pdf non-trivial`);
  }
});

test('no finding is ever produced without citing evidence (AI safety)', async () => {
  // A dataset with NO correlated clusters and NO recurring high/critical rule
  // must yield zero fabricated findings.
  const A = await h.signup('safety@t.com');
  const plain = [
    { id: 's1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '1', level: 2, description: 'benign info', groups: ['ossec'] }, agent: { name: 'x' }, full_log: 'ok' },
    { id: 's2', timestamp: '2026-09-20T10:05:00Z', rule: { id: '2', level: 3, description: 'another benign', groups: ['ossec'] }, agent: { name: 'y' }, full_log: 'ok' },
  ];
  const up = await h.uploadJson(A.token, plain);
  const r = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  const d = r.data.report.data;
  assert.equal(d.findings.length, 0, 'no findings invented');
  assert.equal(d.recommended_actions.length, 0, 'no actions invented');
  assert.match(d.mitre_section.note, /Not enough evidence/);
});
