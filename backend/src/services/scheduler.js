'use strict';
const config = require('../config');
const { query } = require('../db/pool');
const { buildReport } = require('./report/builder');
const { sendReportEmail } = require('./mailer');
const actionsService = require('./actions.service');
const { runRetentionForAllTenants } = require('./retention');

// ---- timezone-aware date math (no external date libs) ----

/** Offset (ms) between the given instant's wall-clock in `tz` and UTC. */
function tzOffsetMs(date, tz) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  const p = dtf.formatToParts(date).reduce((a, x) => ((a[x.type] = x.value), a), {});
  const asUTC = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return asUTC - date.getTime();
}

/** Convert a wall-clock time in `tz` to the corresponding UTC Date. */
function wallTimeToUtc(y, mo, d, hh, mm, tz) {
  const guess = Date.UTC(y, mo, d, hh, mm, 0);
  const off = tzOffsetMs(new Date(guess), tz);
  return new Date(guess - off);
}

/** Local Y/M/D + weekday of an instant in `tz`. */
function localParts(date, tz) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit',
  });
  const p = dtf.formatToParts(date).reduce((a, x) => ((a[x.type] = x.value), a), {});
  const dowMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return { year: +p.year, month: +p.month, day: +p.day, dow: dowMap[p.weekday] };
}

function safeTz(tz) {
  let t = tz || 'UTC';
  try { Intl.DateTimeFormat('en-US', { timeZone: t }); } catch { t = 'UTC'; }
  return t;
}

/**
 * The previous COMPLETED 7-day reporting window for a run at `runAt`, expressed
 * in the schedule's timezone. window = [localMidnight(runAt) - 7 days, localMidnight(runAt)).
 * Half-open so consecutive weeks never overlap and never double-count an event.
 * Timezone-aware so boundaries fall on the tenant's local midnight.
 */
function computeWeeklyWindow(runAt = new Date(), timezone = 'UTC') {
  const tz = safeTz(timezone);
  const lp = localParts(runAt, tz);
  const end = wallTimeToUtc(lp.year, lp.month - 1, lp.day, 0, 0, tz); // local midnight today
  const start = new Date(end.getTime() - 7 * 86400000);
  return { start, end };
}

/**
 * Next occurrence (as a UTC Date) of dow/hour/minute in `tz`, strictly after `from`.
 */
function computeNextRun({ day_of_week, hour, minute, timezone }, from = new Date()) {
  const tz = safeTz(timezone);
  const dow = ((parseInt(day_of_week, 10) % 7) + 7) % 7;
  const hh = Math.min(Math.max(parseInt(hour, 10) || 0, 0), 23);
  const mm = Math.min(Math.max(parseInt(minute, 10) || 0, 0), 59);

  for (let i = 0; i <= 8; i++) {
    const probe = new Date(from.getTime() + i * 86400000);
    const lp = localParts(probe, tz);
    if (lp.dow !== dow) continue;
    const candidate = wallTimeToUtc(lp.year, lp.month - 1, lp.day, hh, mm, tz);
    if (candidate.getTime() > from.getTime()) return candidate;
  }
  return new Date(from.getTime() + 7 * 86400000);
}

// ---- schedule execution ----

/** Count tenant events that fall in the reporting window. */
async function countEventsInWindow(tenantId, window) {
  const r = await query(
    `SELECT count(*)::int c FROM events WHERE tenant_id=$1 AND ts >= $2 AND ts < $3`,
    [tenantId, window.start, window.end]
  );
  return r.rows[0].c;
}

async function recordRun(row) {
  await query(
    `INSERT INTO schedule_runs(tenant_id, schedule_id, run_at, window_start, window_end, event_count, status, report_id, error)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      row.tenant_id, row.schedule_id || null, row.run_at || new Date(),
      row.window_start || null, row.window_end || null, row.event_count || 0,
      row.status, row.report_id || null, row.error || null,
    ]
  );
}

/**
 * Run one schedule now. Produces a WINDOWED weekly report over the previous
 * completed 7-day period (never the whole historical upload):
 *   - no events in window            -> skipped_no_data (no empty report created)
 *   - report already exists for window -> skipped_duplicate
 *   - otherwise                       -> generate scheduled report, email, audit
 * Returns a status string. Every outcome is recorded in schedule_runs.
 */
async function runSchedule(schedule, opts = {}) {
  const now = opts.now || new Date();
  const window = opts.window || computeWeeklyWindow(now, schedule.timezone);

  // Branding snapshot from tenant.
  const t = await query('SELECT company_name, logo_data_url, default_client FROM tenants WHERE id=$1', [schedule.tenant_id]);
  const branding = t.rows[0] || {};
  const clientName = schedule.client_name || branding.default_client || null;

  // 1) No eligible events in the window -> do not create a duplicate empty report.
  const eventCount = await countEventsInWindow(schedule.tenant_id, window);
  if (eventCount === 0) {
    await recordRun({
      tenant_id: schedule.tenant_id, schedule_id: schedule.id, run_at: now,
      window_start: window.start, window_end: window.end, event_count: 0, status: 'skipped_no_data',
    });
    return 'skipped_no_data';
  }

  // 2) Duplicate guard: a scheduled report for this exact window already exists.
  const dup = await query(
    `SELECT id FROM reports WHERE tenant_id=$1 AND report_kind='scheduled' AND period_start=$2 AND period_end=$3 LIMIT 1`,
    [schedule.tenant_id, window.start, window.end]
  );
  if (dup.rowCount) {
    await recordRun({
      tenant_id: schedule.tenant_id, schedule_id: schedule.id, run_at: now,
      window_start: window.start, window_end: window.end, event_count: eventCount, status: 'skipped_duplicate',
      report_id: dup.rows[0].id,
    });
    return 'skipped_duplicate';
  }

  // 3) Build the windowed report across ALL uploads in the window (not one upload).
  const data = await buildReport(schedule.tenant_id, null, {
    title: schedule.name || 'Weekly SOC Report',
    branding,
    clientName,
    window,
  });

  const prevId = data.comparison && data.comparison.available ? data.comparison.previous.report_id : null;

  let reportId;
  try {
    const ins = await query(
      `INSERT INTO reports(tenant_id, user_id, upload_id, title, period_start, period_end, client_name, organization, previous_report_id, report_kind, data)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'scheduled',$10) RETURNING id`,
      [schedule.tenant_id, schedule.created_by, null, data.title, data.period_start, data.period_end, clientName, branding.company_name || null, prevId, JSON.stringify(data)]
    );
    reportId = ins.rows[0].id;
  } catch (e) {
    // Unique-index race: another run created the same window report first.
    if (String(e.message).includes('uq_reports_scheduled_window') || String(e.code) === '23505') {
      await recordRun({
        tenant_id: schedule.tenant_id, schedule_id: schedule.id, run_at: now,
        window_start: window.start, window_end: window.end, event_count: eventCount, status: 'skipped_duplicate',
      });
      return 'skipped_duplicate';
    }
    throw e;
  }

  // Seed the management action plan (dedup by finding_key across reports).
  try {
    await actionsService.seedFromReport(schedule.tenant_id, schedule.created_by, reportId, data.recommended_actions);
  } catch (seedErr) {
    console.error('[scheduler] action seed failed', String(seedErr.message).slice(0, 200));
  }

  // 4) Email delivery (recorded in the outbox; auditable).
  const recipients = Array.isArray(schedule.recipients) ? schedule.recipients : [];
  const periodEnd = data.period_end ? new Date(data.period_end).toISOString().slice(0, 10) : 'n/a';
  const subject = `${data.title}${clientName ? ' — ' + clientName : ''} (${periodEnd})`;
  const body =
    `Your scheduled SOC report is ready.\n\n` +
    `Reporting window: ${new Date(window.start).toISOString().slice(0, 10)} to ${new Date(window.end).toISOString().slice(0, 10)}\n` +
    `Total alerts: ${data.dashboard.totals.total}\n` +
    `Critical: ${data.dashboard.severity.Critical}  High: ${data.dashboard.severity.High}  ` +
    `Medium: ${data.dashboard.severity.Medium}  Low: ${data.dashboard.severity.Low}\n\n` +
    `This report was generated automatically from uploaded Wazuh evidence. ` +
    `All findings cite the underlying event IDs.`;
  await sendReportEmail({ tenantId: schedule.tenant_id, to: recipients, subject, body, reportId });

  await recordRun({
    tenant_id: schedule.tenant_id, schedule_id: schedule.id, run_at: now,
    window_start: window.start, window_end: window.end, event_count: eventCount, status: 'sent', report_id: reportId,
  });
  return 'sent';
}

/**
 * Execute all schedules whose next_run_at is due. Safe to call repeatedly.
 */
async function runDueSchedules(now = new Date()) {
  const due = await query(
    `SELECT * FROM schedules WHERE enabled = true AND next_run_at IS NOT NULL AND next_run_at <= $1`,
    [now]
  );
  const results = [];
  for (const s of due.rows) {
    let status;
    try {
      status = await runSchedule(s, { now });
    } catch (e) {
      status = 'error';
      const safe = String(e.message).slice(0, 200);
      console.error('[scheduler] schedule failed', s.id, safe);
      try {
        await recordRun({ tenant_id: s.tenant_id, schedule_id: s.id, run_at: now, status: 'error', error: safe });
      } catch { /* best-effort audit */ }
    }
    const next = computeNextRun(s, new Date(now.getTime() + 60000));
    await query(
      `UPDATE schedules SET last_run_at=$2, last_status=$3, next_run_at=$4 WHERE id=$1`,
      [s.id, now, status, next]
    );
    results.push({ id: s.id, status, next_run_at: next });
  }
  return results;
}

let timer = null;
let retentionTimer = null;
function startScheduler() {
  if (!config.scheduler.enabled || timer) return;
  timer = setInterval(() => {
    runDueSchedules().catch((e) => console.error('[scheduler] tick error', String(e.message).slice(0, 200)));
  }, config.scheduler.tickMs);
  if (timer.unref) timer.unref();

  // Retention sweep runs on its own (slower) cadence.
  const retentionEvery = Math.max(config.retention.sweepIntervalMs, config.scheduler.tickMs);
  retentionTimer = setInterval(() => {
    runRetentionForAllTenants().catch((e) => console.error('[retention] tick error', String(e.message).slice(0, 200)));
  }, retentionEvery);
  if (retentionTimer.unref) retentionTimer.unref();

  console.log(`[scheduler] started (tick ${config.scheduler.tickMs}ms, retention sweep ${retentionEvery}ms)`);
}
function stopScheduler() {
  if (timer) { clearInterval(timer); timer = null; }
  if (retentionTimer) { clearInterval(retentionTimer); retentionTimer = null; }
}

module.exports = { computeNextRun, computeWeeklyWindow, runDueSchedules, runSchedule, startScheduler, stopScheduler, countEventsInWindow };
