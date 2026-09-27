'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');
const { computeNextRun, computeWeeklyWindow, runDueSchedules, runSchedule } = require('../src/services/scheduler');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

// Build one alert at an explicit ISO timestamp.
function alertAt(iso, id = 'a', level = 12) {
  return { id, timestamp: iso, rule: { id: '5710', level, description: 'ssh fail', groups: ['sshd', 'authentication_failed'], mitre: { id: ['T1110'] } }, agent: { name: 'web01' }, data: { srcip: '203.0.113.1', dstuser: 'root' }, full_log: 'x' };
}

// Create a pro-plan tenant + a schedule, and return { A, scheduleRow }.
async function makeSchedule(email, body = {}) {
  const A = await h.signup(email);
  await h.setPlan(A.tenant.id, 'pro');
  const created = await h.req('POST', '/api/schedules', { token: A.token, body: { name: 'Weekly', day_of_week: 1, hour: 8, minute: 0, timezone: 'UTC', recipients: ['ciso@acme.com'], ...body } });
  const row = (await h.pool.query('SELECT * FROM schedules WHERE id=$1', [created.data.schedule.id])).rows[0];
  return { A, scheduleRow: row };
}

// ---------- next-run computation (unchanged behavior) ----------

test('computeNextRun returns the next matching weekday/time in the future', () => {
  const from = new Date('2026-09-23T09:00:00Z'); // Wed
  const next = computeNextRun({ day_of_week: 1, hour: 8, minute: 0, timezone: 'UTC' }, from);
  assert.equal(next.getUTCDay(), 1);
  assert.equal(next.getUTCHours(), 8);
  assert.ok(next.getTime() > from.getTime());
  assert.equal(next.toISOString().slice(0, 10), '2026-09-28');
});

test('computeNextRun respects timezone offset', () => {
  const from = new Date('2026-09-23T00:00:00Z');
  const next = computeNextRun({ day_of_week: 3, hour: 8, minute: 0, timezone: 'Asia/Kolkata' }, from);
  assert.equal(next.getUTCHours(), 2);
  assert.equal(next.getUTCMinutes(), 30);
});

// ---------- M1: weekly windowing ----------

test('M1: computeWeeklyWindow is the previous completed 7-day period at local midnight', () => {
  const runAt = new Date('2026-09-28T08:00:00Z'); // Monday 08:00 UTC
  const w = computeWeeklyWindow(runAt, 'UTC');
  assert.equal(w.end.toISOString(), '2026-09-28T00:00:00.000Z');
  assert.equal(w.start.toISOString(), '2026-09-21T00:00:00.000Z');
  // exactly 7 days
  assert.equal((w.end - w.start) / 86400000, 7);
});

test('M1: timezone boundaries align the window to the tenant local midnight', () => {
  const runAt = new Date('2026-09-28T02:00:00Z'); // still Sun 21:30 in US/Eastern? use Kolkata
  const w = computeWeeklyWindow(runAt, 'Asia/Kolkata'); // UTC+5:30
  // Local date at runAt in Kolkata is 2026-09-28 07:30 -> local midnight = 2026-09-27T18:30:00Z
  assert.equal(w.end.toISOString(), '2026-09-27T18:30:00.000Z');
  assert.equal(w.start.toISOString(), '2026-09-20T18:30:00.000Z');
});

test('M1: scheduling requires an entitled plan', async () => {
  const A = await h.signup('sched-free@t.com');
  await h.setPlan(A.tenant.id, 'free');
  const r = await h.req('POST', '/api/schedules', { token: A.token, body: { day_of_week: 1, hour: 8, minute: 0, timezone: 'UTC', recipients: ['soc@acme.com'] } });
  assert.equal(r.status, 402);
});

test('M1: create schedule computes next_run_at and filters invalid recipients', async () => {
  const A = await h.signup('sched@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const r = await h.req('POST', '/api/schedules', { token: A.token, body: { name: 'Weekly', day_of_week: 1, hour: 8, minute: 30, timezone: 'UTC', recipients: ['soc@acme.com', 'not an email'] } });
  assert.equal(r.status, 201);
  assert.ok(r.data.schedule.next_run_at);
  assert.deepEqual(r.data.schedule.recipients, ['soc@acme.com']);
});

test('M1: a normal weekly window generates a windowed report scoped to the period', async () => {
  const { A, scheduleRow } = await makeSchedule('sched-win@t.com');
  const window = { start: new Date('2026-09-21T00:00:00Z'), end: new Date('2026-09-28T00:00:00Z') };
  // 3 in-window alerts + 2 out-of-window (before + after) — only the 3 must count.
  await h.uploadJson(A.token, [
    alertAt('2026-09-14T10:00:00Z', 'before'),       // before window
    alertAt('2026-09-22T10:00:00Z', 'in1'),
    alertAt('2026-09-23T10:00:00Z', 'in2'),
    alertAt('2026-09-24T10:00:00Z', 'in3'),
    alertAt('2026-09-29T10:00:00Z', 'after'),        // after window
  ]);

  const status = await runSchedule(scheduleRow, { now: new Date('2026-09-28T08:00:00Z'), window });
  assert.equal(status, 'sent');

  const rep = await h.pool.query("SELECT report_kind, period_start, period_end, data FROM reports WHERE tenant_id=$1", [A.tenant.id]);
  assert.equal(rep.rowCount, 1);
  assert.equal(rep.rows[0].report_kind, 'scheduled');
  assert.equal(new Date(rep.rows[0].period_start).toISOString(), window.start.toISOString());
  assert.equal(new Date(rep.rows[0].period_end).toISOString(), window.end.toISOString());
  // ONLY the 3 in-window events were analyzed (not the whole upload of 5).
  assert.equal(rep.rows[0].data.dashboard.totals.total, 3);

  const run = await h.pool.query("SELECT status, event_count FROM schedule_runs WHERE tenant_id=$1", [A.tenant.id]);
  assert.equal(run.rows[0].status, 'sent');
  assert.equal(run.rows[0].event_count, 3);
});

test('M1: a no-data window is skipped and does not create an empty report', async () => {
  const { A, scheduleRow } = await makeSchedule('sched-nodata@t.com');
  const window = { start: new Date('2026-09-21T00:00:00Z'), end: new Date('2026-09-28T00:00:00Z') };
  await h.uploadJson(A.token, [alertAt('2026-08-01T10:00:00Z', 'old')]); // outside window

  const status = await runSchedule(scheduleRow, { now: new Date('2026-09-28T08:00:00Z'), window });
  assert.equal(status, 'skipped_no_data');
  const rep = await h.pool.query('SELECT count(*)::int c FROM reports WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(rep.rows[0].c, 0);
  const run = await h.pool.query("SELECT status FROM schedule_runs WHERE tenant_id=$1", [A.tenant.id]);
  assert.equal(run.rows[0].status, 'skipped_no_data');
});

test('M1: duplicate scheduler execution for the same window does not create a second report', async () => {
  const { A, scheduleRow } = await makeSchedule('sched-dup@t.com');
  const window = { start: new Date('2026-09-21T00:00:00Z'), end: new Date('2026-09-28T00:00:00Z') };
  await h.uploadJson(A.token, [alertAt('2026-09-22T10:00:00Z', 'in1'), alertAt('2026-09-23T10:00:00Z', 'in2')]);

  const s1 = await runSchedule(scheduleRow, { now: new Date('2026-09-28T08:00:00Z'), window });
  const s2 = await runSchedule(scheduleRow, { now: new Date('2026-09-28T08:05:00Z'), window });
  assert.equal(s1, 'sent');
  assert.equal(s2, 'skipped_duplicate');

  const rep = await h.pool.query('SELECT count(*)::int c FROM reports WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(rep.rows[0].c, 1);
  const runs = await h.pool.query("SELECT status FROM schedule_runs WHERE tenant_id=$1 ORDER BY run_at", [A.tenant.id]);
  assert.deepEqual(runs.rows.map((r) => r.status), ['sent', 'skipped_duplicate']);
});

test('M1: overlapping vs distinct windows — distinct periods each produce a report', async () => {
  const { A, scheduleRow } = await makeSchedule('sched-overlap@t.com');
  const w1 = { start: new Date('2026-09-14T00:00:00Z'), end: new Date('2026-09-21T00:00:00Z') };
  const w2 = { start: new Date('2026-09-21T00:00:00Z'), end: new Date('2026-09-28T00:00:00Z') };
  await h.uploadJson(A.token, [alertAt('2026-09-16T10:00:00Z', 'w1a', 6), alertAt('2026-09-23T10:00:00Z', 'w2a', 12)]);

  const r1 = await runSchedule(scheduleRow, { now: new Date('2026-09-21T08:00:00Z'), window: w1 });
  const r2 = await runSchedule(scheduleRow, { now: new Date('2026-09-28T08:00:00Z'), window: w2 });
  assert.equal(r1, 'sent');
  assert.equal(r2, 'sent');

  const reps = await h.pool.query('SELECT period_start, period_end, data FROM reports WHERE tenant_id=$1 ORDER BY period_start', [A.tenant.id]);
  assert.equal(reps.rowCount, 2);
  assert.equal(reps.rows[0].data.dashboard.totals.total, 1); // only w1 event
  assert.equal(reps.rows[1].data.dashboard.totals.total, 1); // only w2 event
  // Chronological comparison: the second (later) report compares against the first.
  assert.equal(reps.rows[1].data.comparison.available, true);
});

test('M1: run-now endpoint triggers a windowed schedule immediately (Analyst+)', async () => {
  const A = await h.signup('sched-now@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const inWindow = new Date(Date.now() - 2 * 86400000);
  await h.uploadJson(A.token, [alertAt(inWindow.toISOString(), 'recent')]);
  const created = await h.req('POST', '/api/schedules', { token: A.token, body: { recipients: ['a@b.com'] } });
  const run = await h.req('POST', '/api/schedules/' + created.data.schedule.id + '/run', { token: A.token });
  assert.equal(run.status, 200);
  assert.equal(run.data.status, 'sent');
});

test('M1: due schedule runs via the loop and records an outbox email', async () => {
  const { A, scheduleRow } = await makeSchedule('sched-loop@t.com');
  // Put an event inside the window that the loop will compute from `now`.
  const now = new Date();
  const inWindow = new Date(now.getTime() - 2 * 86400000); // 2 days ago (within previous 7d, before today midnight)
  await h.uploadJson(A.token, [alertAt(inWindow.toISOString(), 'recent')]);
  await h.pool.query("UPDATE schedules SET next_run_at = now() - interval '1 minute' WHERE id=$1", [scheduleRow.id]);

  const results = await runDueSchedules(new Date());
  assert.equal(results.length, 1);
  assert.equal(results[0].status, 'sent');

  const outbox = await h.pool.query('SELECT to_addrs, status FROM email_outbox WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(outbox.rowCount, 1);
  assert.deepEqual(outbox.rows[0].to_addrs, ['ciso@acme.com']);

  const after = await h.pool.query('SELECT next_run_at, last_status FROM schedules WHERE id=$1', [scheduleRow.id]);
  assert.ok(new Date(after.rows[0].next_run_at).getTime() > Date.now());
  assert.equal(after.rows[0].last_status, 'sent');
});
