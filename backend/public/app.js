'use strict';
/* SOC Report Copilot SPA. Uploaded/derived values are rendered via textContent /
   DOM construction (never innerHTML) so log content can never inject markup. */

const state = {
  token: localStorage.getItem('soc_token') || null,
  me: null, cfg: null, uploadId: null, authMode: 'signup',
};
const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

// ---------- helpers ----------
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k === 'html') n.innerHTML = v; // used ONLY with our own static strings
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids) { if (kid == null) continue; n.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid); }
  return n;
}
function toast(msg, kind) {
  const t = el('div', { class: 'toast ' + (kind || 'ok'), text: msg });
  document.body.appendChild(t); setTimeout(() => t.remove(), 4000);
}
async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  if (opts.body && !(opts.body instanceof FormData)) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.body); }
  const res = await fetch('/api' + path, { ...opts, headers });
  const ct = res.headers.get('content-type') || '';
  if (!res.ok) { let m = res.statusText; if (ct.includes('json')) { try { m = (await res.json()).error || m; } catch {} } const e = new Error(m); e.status = res.status; throw e; }
  return ct.includes('json') ? res.json() : res;
}
function can(minRole) {
  const rank = { viewer: 1, analyst: 2, admin: 3 };
  return state.me && (rank[state.me.role] || 0) >= rank[minRole];
}
function applyRoleVisibility() {
  $$('[data-role]').forEach((n) => { n.classList.toggle('hidden', !can(n.dataset.role)); });
}
function sevClass(s) { return { Critical: 'sev-crit', High: 'sev-high', Medium: 'sev-med', Low: 'sev-low' }[s] || ''; }
function barClass(s) { return { Critical: 'b-crit', High: 'b-high', Medium: 'b-med', Low: 'b-low' }[s] || 'b-acc'; }
function fmtDate(d) { return d ? new Date(d).toLocaleString() : 'n/a'; }
function dstr(d) { return d ? new Date(d).toISOString().slice(0, 10) : 'n/a'; }

// ---------- landing: pricing ----------
function renderPricing(container, opts = {}) {
  container.textContent = '';
  const plans = (state.cfg && state.cfg.plans) || [];
  for (const p of plans) {
    const featured = p.id === 'pro';
    const card = el('div', { class: 'price' + (featured ? ' featured' : '') });
    if (featured) card.appendChild(el('span', { class: 'badge', text: 'Most popular' }));
    card.appendChild(el('h3', { text: p.name }));
    card.appendChild(el('div', { class: 'muted', text: p.blurb, style: 'font-size:13px;min-height:38px' }));
    card.appendChild(el('div', { class: 'amt' }, `$${p.price_monthly}`, el('small', { text: '/mo' })));
    const ul = el('ul', {});
    for (const f of p.features) ul.appendChild(el('li', { text: f }));
    card.appendChild(ul);
    if (opts.inApp) {
      const cur = state.tenantPlan === p.id;
      card.appendChild(el('button', { class: 'btn' + (cur ? ' secondary' : ''), disabled: cur ? '' : null,
        text: cur ? 'Current plan' : `Switch to ${p.name}`, onclick: () => changePlan(p.id) }));
    } else {
      card.appendChild(el('button', { class: 'btn' + (featured ? '' : ' secondary'), text: p.price_monthly === 0 ? 'Start free' : `Choose ${p.name}`, onclick: () => openAuth('signup') }));
    }
    container.appendChild(card);
  }
}

// ---------- auth ----------
function openAuth(mode) {
  state.authMode = mode || 'signup';
  $('#authModal').classList.remove('hidden');
  $$('[data-auth]').forEach((x) => x.classList.toggle('active', x.dataset.auth === state.authMode));
  $('#signupOnly').classList.toggle('hidden', state.authMode !== 'signup');
  $('#authBtn').textContent = state.authMode === 'signup' ? 'Create account' : 'Log in';
  $('#demoHint').style.display = state.cfg && state.cfg.demoMode ? 'block' : 'none';
}
$('#authClose').addEventListener('click', () => $('#authModal').classList.add('hidden'));
$$('[data-auth]').forEach((t) => t.addEventListener('click', () => openAuth(t.dataset.auth)));
['navLogin'].forEach((id) => $('#' + id).addEventListener('click', (e) => { e.preventDefault(); openAuth('login'); }));
['navSignup', 'heroSignup'].forEach((id) => $('#' + id).addEventListener('click', (e) => { e.preventDefault(); openAuth('signup'); }));

$('#authBtn').addEventListener('click', async () => {
  const email = $('#email').value.trim(), password = $('#password').value;
  try {
    const path = state.authMode === 'signup' ? '/auth/signup' : '/auth/login';
    const body = { email, password };
    if (state.authMode === 'signup') body.tenantName = $('#tenantName').value.trim();
    const r = await api(path, { method: 'POST', body });
    state.token = r.token; localStorage.setItem('soc_token', r.token);
    $('#authModal').classList.add('hidden');
    await boot();
    toast('Welcome, ' + r.user.email);
  } catch (e) { toast(e.message, 'err'); }
});
$('#logoutBtn').addEventListener('click', () => { localStorage.removeItem('soc_token'); state.token = null; state.me = null; showLanding(); });

function showLanding() { $('#landing').classList.remove('hidden'); $('#app').classList.add('hidden'); }
function showApp() { $('#landing').classList.add('hidden'); $('#app').classList.remove('hidden'); }

// ---------- app tabs ----------
$$('[data-view]').forEach((t) => t.addEventListener('click', () => gotoView(t.dataset.view)));
function gotoView(v) {
  $$('[data-view]').forEach((x) => x.classList.toggle('active', x.dataset.view === v));
  ['dashboard', 'uploads', 'findings', 'reports', 'actions', 'history', 'settings'].forEach((s) => $('#v-' + s).classList.toggle('hidden', s !== v));
  if (v === 'dashboard') loadExec();
  if (v === 'uploads') loadDashboard();
  if (v === 'findings') loadFindings();
  if (v === 'reports') loadReports();
  if (v === 'actions') loadActions();
  if (v === 'history') loadHistory();
  if (v === 'settings') loadSettings();
}

// ---------- onboarding ----------
async function renderOnboarding() {
  const uploads = state._uploads || [];
  const reports = state._reports || [];
  const hasUpload = uploads.some((u) => u.status === 'parsed');
  const hasReport = reports.length > 0;
  const box = $('#onboarding');
  if (localStorage.getItem('soc_onb_dismissed') === '1' || (hasUpload && hasReport)) { box.classList.add('hidden'); return; }
  box.classList.remove('hidden');
  const steps = $('#onbSteps'); steps.textContent = '';
  const step = (n, done, title, desc, action) => {
    const s = el('div', { class: 'ostep' + (done ? ' done' : '') },
      el('div', { class: 'h' }, el('span', { class: 'dot' + (done ? ' ok' : ''), text: done ? '✓' : String(n) }), title),
      el('div', { class: 'muted', style: 'font-size:13px;margin-bottom:10px', text: desc }));
    if (action && !done) s.appendChild(action);
    return s;
  };
  steps.appendChild(step(1, true, 'Create account', 'Your organization is ready.'));
  steps.appendChild(step(2, hasUpload, 'Upload & validate Wazuh data', 'Upload a JSON/CSV export (or try our synthetic sample). Events are normalized and validated on ingest — malformed rows are skipped and the parsed count is shown.',
    can('analyst') ? el('div', { class: 'row' },
      el('button', { class: 'btn sm', text: 'Load sample data', onclick: loadSampleData }),
      el('button', { class: 'btn sm secondary', text: 'Upload file', onclick: () => $('#obFile').click() }),
      el('input', { id: 'obFile', type: 'file', accept: '.json,.csv,.ndjson,.log', class: 'hidden', onchange: (e) => uploadFile(e.target.files[0]) })
    ) : el('div', { class: 'muted', text: 'Ask an Analyst/Admin to upload.' })));
  steps.appendChild(step(3, hasReport, 'Generate first report', 'Produce an evidence-based executive + analyst report (with PDF).',
    can('analyst') ? el('button', { class: 'btn sm', text: 'Generate report', disabled: hasUpload ? null : '', onclick: () => generateReport(state.uploadId) }) : null));
  steps.appendChild(step(4, hasReport, 'Review the executive summary', 'Open the Executive Overview to see posture, priority actions, and what changed.',
    el('button', { class: 'btn sm secondary', text: 'Go to Executive Overview', onclick: () => gotoView('dashboard') })));
}
$('#onbDismiss').addEventListener('click', () => { localStorage.setItem('soc_onb_dismissed', '1'); $('#onboarding').classList.add('hidden'); });

async function loadSampleData() {
  try { const r = await api('/uploads/sample', { method: 'POST' }); state.uploadId = r.upload.id; toast(`Loaded ${r.event_count} sample events`); await refreshUploads(); await loadExec(); await loadDashboard(); await renderOnboarding(); }
  catch (e) { toast(e.message, 'err'); }
}
async function uploadFile(file) {
  if (!file) return;
  const fd = new FormData(); fd.append('file', file); fd.append('sourceType', 'wazuh');
  try { const r = await api('/uploads', { method: 'POST', body: fd }); state.uploadId = r.upload.id; toast(`Ingested ${r.event_count} events` + (r.truncated ? ' (truncated)' : '')); await refreshUploads(); await loadExec(); await loadDashboard(); await renderOnboarding(); }
  catch (e) { toast(e.message, 'err'); }
}

// ---------- uploads ----------
async function refreshUploads() {
  const { uploads } = await api('/uploads');
  state._uploads = uploads;
  const parsed = uploads.filter((u) => u.status === 'parsed');
  if (!state.uploadId && parsed.length) state.uploadId = parsed[0].id;
  for (const id of ['#uploadSelect', '#execUploadSelect', '#repUploadSelect']) {
    const sel = $(id); if (!sel) continue;
    sel.textContent = '';
    for (const u of parsed) sel.appendChild(el('option', { value: u.id, text: `${u.filename} · ${u.event_count} events · ${dstr(u.uploaded_at)}` }));
    if (state.uploadId) sel.value = state.uploadId;
  }
}
$('#uploadSelect').addEventListener('change', (e) => { state.uploadId = e.target.value; refreshUploads(); loadDashboard(); });
$('#execUploadSelect').addEventListener('change', (e) => { state.uploadId = e.target.value; refreshUploads(); loadExec(); });
$('#repUploadSelect').addEventListener('change', (e) => { state.uploadId = e.target.value; refreshUploads(); });
$('#dashGenBtn').addEventListener('click', () => generateReport(state.uploadId));
$('#execGenBtn').addEventListener('click', () => generateReport(state.uploadId));
$('#repGenBtn').addEventListener('click', () => generateReport(state.uploadId));
$('#upSampleBtn').addEventListener('click', loadSampleData);
$('#upFileBtn').addEventListener('click', () => $('#upFileInput').click());
$('#upFileInput').addEventListener('change', (e) => uploadFile(e.target.files[0]));
// Settings sub-tabs
$$('[data-stab]').forEach((t) => t.addEventListener('click', () => {
  $$('[data-stab]').forEach((x) => x.classList.toggle('active', x === t));
  ['general', 'team', 'schedule', 'danger'].forEach((s) => $('#stab-' + s).classList.toggle('hidden', s !== t.dataset.stab));
  if (t.dataset.stab === 'team') loadTeam();
  if (t.dataset.stab === 'schedule') loadSchedules();
}));

// ---------- dashboard ----------
function topTable(title, rows, keyName) {
  const body = el('tbody', {});
  if (!rows || !rows.length) body.appendChild(el('tr', {}, el('td', { colspan: '2', class: 'muted', text: 'None' })));
  for (const r of (rows || []).slice(0, 8)) body.appendChild(el('tr', {}, el('td', { text: String(r.key) }), el('td', { text: String(r.count) })));
  return el('div', { class: 'split' }, el('h3', { text: title }),
    el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: keyName }), el('th', { text: 'Count' }))), body));
}
async function loadDashboard() {
  await refreshUploads();
  const body = $('#dashBody');
  if (!state.uploadId) { body.textContent = ''; body.appendChild(el('div', { class: 'card muted', text: 'No parsed uploads yet.' })); return; }
  try {
    const d = await api('/dashboard?uploadId=' + encodeURIComponent(state.uploadId));
    body.textContent = '';
    const total = Math.max(1, d.totals.total);

    const grid = el('div', { class: 'grid', style: 'grid-template-columns:repeat(5,1fr)' });
    grid.appendChild(el('div', { class: 'kpi' }, el('div', { class: 'n', text: String(d.totals.total) }), el('div', { class: 'l', text: 'Total alerts' })));
    for (const s of ['Critical', 'High', 'Medium', 'Low'])
      grid.appendChild(el('div', { class: 'kpi' }, el('div', { class: 'n ' + sevClass(s), text: String(d.severity[s]) }), el('div', { class: 'l', text: s })));
    body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('h3', { text: 'Overview' }), grid,
      el('div', { class: 'muted', style: 'font-size:12px;margin-top:10px', text: `Window: ${dstr(d.totals.first_seen)} → ${dstr(d.totals.last_seen)}` })));

    const bars = el('div', {});
    for (const s of ['Critical', 'High', 'Medium', 'Low']) {
      const pct = Math.round((d.severity[s] / total) * 100);
      bars.appendChild(el('div', { class: 'barrow' }, el('div', { class: 'd', text: s }),
        el('div', { class: 'bar ' + barClass(s), style: `width:${Math.max(3, pct * 2.4)}px` }), el('span', { class: 'muted', text: `${d.severity[s]} (${pct}%)` })));
    }
    const tr = el('div', {});
    const maxT = Math.max(1, ...d.trend.map((x) => x.count));
    for (const t of d.trend) tr.appendChild(el('div', { class: 'barrow' }, el('div', { class: 'd', text: t.day }),
      el('div', { class: 'bar b-acc', style: `width:${Math.max(3, Math.round((t.count / maxT) * 240))}px` }), el('span', { class: 'muted', text: String(t.count) })));
    body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('div', { class: 'row' },
      el('div', { class: 'split' }, el('h3', { text: 'Severity distribution' }), bars),
      el('div', { class: 'split' }, el('h3', { text: 'Daily alert trend' }), d.trend.length ? tr : el('span', { class: 'muted', text: 'No timestamps in data' })))));

    body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('div', { class: 'row' },
      topTable('Top alert types', d.top_alert_types, 'Rule'), topTable('Top source IPs', d.top_source_ips, 'Source IP'))));
    body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('div', { class: 'row' },
      topTable('Top affected users', d.top_users, 'User'), topTable('Top affected hosts', d.top_hosts, 'Host'))));

    const mt = el('tbody', {});
    if (!d.top_mitre.length) mt.appendChild(el('tr', {}, el('td', { colspan: '2', class: 'muted', text: 'Not enough evidence.' })));
    for (const m of d.top_mitre) mt.appendChild(el('tr', {}, el('td', { text: m.technique_id }), el('td', { text: String(m.count) })));
    body.appendChild(el('div', { class: 'card' }, el('h3', { text: 'MITRE ATT&CK (from alert metadata)' }),
      el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'Technique' }), el('th', { text: 'Alerts' }))), mt)));
  } catch (e) { toast(e.message, 'err'); }
}

// ---------- executive overview ----------
function postureCard(p) {
  const lvl = (p && p.level) || 'stable';
  return el('div', { class: 'card', style: 'margin-bottom:16px' },
    el('div', { class: 'posture' },
      el('div', { class: 'pbar pb-' + lvl }),
      el('div', {},
        el('div', { class: 'muted', style: 'font-size:11px;letter-spacing:.6px', text: 'OVERALL SECURITY POSTURE' }),
        el('div', { class: 'plabel p-' + lvl, text: (p && p.label) || 'Not determined' }),
        el('div', { class: 'muted', style: 'font-size:12px;margin-top:4px', text: (p && p.rationale) || '' }))));
}
async function loadExec() {
  await refreshUploads();
  const body = $('#execBody');
  const q = state.uploadId ? '?uploadId=' + encodeURIComponent(state.uploadId) : '';
  let d; try { d = await api('/dashboard/executive' + q); } catch (e) { toast(e.message, 'err'); return; }
  body.textContent = '';
  if (!d.has_data) { body.appendChild(el('div', { class: 'card muted', text: d.note || 'No data yet.' })); return; }
  body.appendChild(postureCard(d.posture));

  const kpi = (n, l, cls) => el('div', { class: 'kpi' }, el('div', { class: 'n ' + (cls || ''), text: String(n) }), el('div', { class: 'l', text: l }));
  const scopeTag = (t) => el('span', { class: 'badge', style: 'font-size:10px;margin-left:8px;vertical-align:middle', text: t });

  // M5: upload-scoped metrics are clearly separated from tenant-wide ones.
  const upGrid = el('div', { class: 'grid', style: 'grid-template-columns:repeat(4,1fr)' });
  upGrid.appendChild(kpi(d.totals.total, 'Total alerts'));
  upGrid.appendChild(kpi(d.totals.critical, 'Critical', 'sev-crit'));
  upGrid.appendChild(kpi(d.totals.high, 'High', 'sev-high'));
  upGrid.appendChild(kpi(d.false_positive_candidates, 'FP candidates'));
  body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' },
    el('div', {}, el('b', { text: 'Current Upload' }), scopeTag('this data source')),
    el('div', { class: 'muted', style: 'font-size:12px;margin:6px 0 10px', text: `Data source: ${d.data_source ? d.data_source.filename : 'n/a'} · Period ${dstr(d.reporting_period.start)} → ${dstr(d.reporting_period.end)} · Repeated (3+×) ${d.activity.recurring_alerts} / Low-frequency ${d.activity.new_alerts} alerts` }),
    upGrid));

  const twGrid = el('div', { class: 'grid', style: 'grid-template-columns:repeat(3,1fr)' });
  twGrid.appendChild(kpi(d.findings_count, 'Findings (this upload)'));
  twGrid.appendChild(kpi(d.open_findings, 'Open actions', 'sev-high'));
  twGrid.appendChild(kpi(d.resolved_findings, 'Resolved actions', 'sev-low'));
  body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' },
    el('div', {}, el('b', { text: 'All Open Actions' }), scopeTag('tenant-wide — across all reports')),
    el('div', { class: 'muted', style: 'font-size:12px;margin:6px 0 10px', text: 'Management action plan totals span every report for this organization, not just the current upload.' }),
    twGrid));

  const pa = el('div', { class: 'card', style: 'margin-bottom:16px' }, el('h3', { text: 'Priority actions management should know' }));
  if (!d.priority_actions.length) pa.appendChild(el('div', { class: 'muted', text: 'No priority actions.' }));
  for (const a of d.priority_actions) pa.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('span', { class: 'pri pri-' + a.priority, text: a.priority }), ' ', el('b', { text: a.finding }), ' ', el('span', { class: 'aiflag', text: 'AI-assisted' })),
    el('div', { class: 'muted', style: 'font-size:12px;margin-top:4px', text: a.recommended_action }),
    el('div', { class: 'muted', style: 'font-size:12px', text: 'Owner: ' + (a.owner || '—') })));
  body.appendChild(pa);

  body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('div', { class: 'row' },
    topTable('Top affected hosts', d.top_hosts, 'Host'), topTable('Top affected users', d.top_users, 'User'))));
  body.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('div', { class: 'row' },
    topTable('Top alert categories', d.top_alert_types, 'Category'), topTable('Recurring source IPs', d.recurring_source_ips, 'Source IP'))));

  const mt = el('tbody', {});
  if (!d.mitre_overview.length) mt.appendChild(el('tr', {}, el('td', { colspan: '3', class: 'muted', text: d.mitre_note || 'Not enough evidence.' })));
  for (const m of d.mitre_overview) mt.appendChild(el('tr', {}, el('td', { text: m.tactic || 'n/a' }), el('td', { text: (m.technique_name || '') + ' (' + m.technique_id + ')' }), el('td', { text: String(m.alert_count) })));
  body.appendChild(el('div', { class: 'card' }, el('h3', { text: 'MITRE ATT&CK overview (evidence-gated)' }),
    el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'Tactic' }), el('th', { text: 'Technique' }), el('th', { text: 'Alerts' }))), mt)));
}

// ---------- findings ----------
async function loadFindings() {
  const reports = await loadReportsData();
  const body = $('#findingsBody'); body.textContent = '';
  if (!reports.length) { body.appendChild(el('div', { class: 'card muted', text: 'No reports yet — generate one from Uploads or Reports.' })); return; }
  const { report } = await api('/reports/' + reports[0].id);
  const d = report.data;
  body.appendChild(el('div', { class: 'card', style: 'margin-bottom:12px' }, el('div', { class: 'muted', style: 'font-size:13px', text: `From report "${d.title}" · ${dstr(d.period_start)} → ${dstr(d.period_end)} · ${d.findings.length} findings` })));
  if (!d.findings.length) { body.appendChild(el('div', { class: 'card muted', text: 'No findings met the reporting threshold — no fabricated findings are shown.' })); return; }
  for (const f of d.findings) body.appendChild(el('div', { class: 'card', style: 'margin-bottom:12px' },
    el('div', { class: 'row', style: 'justify-content:space-between;align-items:flex-start' },
      el('div', { style: 'flex:1;min-width:240px' }, el('b', { text: f.title })),
      el('div', {}, el('span', { class: 'pill ' + barClass(f.severity), style: 'color:#fff', text: f.severity }), ' ', el('span', { class: 'badge', text: f.confidence + ' confidence' }))),
    el('div', { style: 'margin:8px 0', text: f.description }),
    el('div', { class: 'muted', style: 'font-size:12px', text: 'Affected assets: ' + ((f.evidence.assets || []).join(', ') || 'n/a') }),
    el('div', { class: 'muted', style: 'font-size:12px', text: `Time span: ${fmtDate(f.evidence.first_seen)} → ${fmtDate(f.evidence.last_seen)}` }),
    evidenceLine(f.evidence.event_ids)));
}

// ---------- actions (management action plan) ----------
async function loadActions() {
  const filt = $('#actionFilter');
  if (!filt._init) {
    [['', 'All statuses'], ['open', 'Open'], ['investigating', 'Investigating'], ['resolved', 'Resolved'], ['accepted_risk', 'Accepted risk']]
      .forEach(([v, t]) => filt.appendChild(el('option', { value: v, text: t })));
    filt._init = true; filt.addEventListener('change', loadActions);
  }
  const status = filt.value;
  const { actions } = await api('/actions' + (status ? '?status=' + status : ''));
  const body = $('#actionsBody'); body.textContent = '';
  if (!actions.length) { body.appendChild(el('div', { class: 'card muted', text: 'No actions. Generate a report to seed the action plan.' })); return; }
  for (const a of actions) {
    const card = el('div', { class: 'card', style: 'margin-bottom:12px' });
    const statusSel = el('select', { style: 'width:160px', disabled: can('analyst') ? null : '',
      onchange: async (e) => { const note = prompt('Note for this status change (optional):') || undefined; try { await api('/actions/' + a.id, { method: 'PATCH', body: { status: e.target.value, note } }); toast('Status updated'); loadActions(); } catch (err) { toast(err.message, 'err'); loadActions(); } } });
    ['open', 'investigating', 'resolved', 'accepted_risk'].forEach((s) => statusSel.appendChild(el('option', { value: s, text: s.replace('_', ' '), selected: a.status === s ? '' : null })));
    card.appendChild(el('div', { class: 'row', style: 'justify-content:space-between;align-items:flex-start' },
      el('div', { style: 'flex:1;min-width:240px' },
        el('div', {}, el('span', { class: 'pri pri-' + a.priority, text: a.priority }), ' ', el('b', { text: a.finding }), ' ', el('span', { class: 'sp sp-' + a.status, text: a.status.replace('_', ' ') }), ' ', a.ai_assisted ? el('span', { class: 'aiflag', text: 'AI-assisted' }) : null),
        el('div', { class: 'muted', style: 'font-size:13px;margin:6px 0', text: a.recommended_action }),
        el('div', { class: 'muted', style: 'font-size:12px', text: 'Owner: ' + (a.owner || '—') + ' · updated ' + fmtDate(a.updated_at) }),
        evidenceLine(a.evidence && a.evidence.event_ids)),
      el('div', {}, statusSel)));
    const hbtn = el('button', { class: 'btn sm ghost', text: 'View audit history', onclick: async () => {
      const { action } = await api('/actions/' + a.id);
      const h = el('div', { class: 'hist', style: 'margin-top:10px' });
      for (const x of action.history) h.appendChild(el('div', { class: 'hi' }, el('span', { class: 'muted', text: fmtDate(x.changed_at) + ': ' }), (x.from_status ? x.from_status + ' → ' : '') + x.to_status + (x.note ? ' — ' + x.note : '')));
      card.appendChild(h); hbtn.remove();
    } });
    card.appendChild(el('div', { style: 'margin-top:8px' }, hbtn));
    body.appendChild(card);
  }
}

// ---------- history & comparison ----------
async function loadHistory() {
  const reports = await loadReportsData();
  const body = $('#historyBody'); body.textContent = '';
  if (!reports.length) { body.appendChild(el('div', { class: 'card muted', text: 'No reports yet.' })); return; }
  const { report } = await api('/reports/' + reports[0].id);
  const c = report.data.comparison;
  const cc = el('div', { class: 'card', style: 'margin-bottom:16px' }, el('h3', { text: 'Latest report vs previous' }));
  if (!c || !c.available) {
    cc.appendChild(el('div', { class: 'muted', text: (c && c.note) || 'Historical comparison unavailable.' }));
  } else {
    cc.appendChild(el('div', { class: 'muted', style: 'font-size:13px;margin-bottom:10px', text: c.note }));
    const dir = (x) => x.direction === 'increased' ? 'cmp-up' : x.direction === 'decreased' ? 'cmp-down' : 'cmp-flat';
    const tb = el('tbody', {});
    const trow = (label, prev, cur, delta, cls) => el('tr', {}, el('td', { text: label }), el('td', { text: String(prev) }), el('td', { text: String(cur) }), el('td', { class: cls || '', text: String(delta) }));
    tb.appendChild(trow('Total alerts', c.alert_volume.previous, c.alert_volume.current, `${c.alert_volume.delta >= 0 ? '+' : ''}${c.alert_volume.delta}`, dir(c.alert_volume)));
    tb.appendChild(trow('High + Critical', c.severity.previous.Critical + c.severity.previous.High, c.severity.current.Critical + c.severity.current.High, `${c.severity.high_critical_delta >= 0 ? '+' : ''}${c.severity.high_critical_delta}`, dir(c.severity)));
    cc.appendChild(el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'Metric' }), el('th', { text: 'Previous' }), el('th', { text: 'Current' }), el('th', { text: 'Change' }))), tb));
  }
  body.appendChild(cc);
  const lst = el('div', { class: 'card' }, el('h3', { text: 'All reports' }));
  for (const r of reports) lst.appendChild(el('div', { class: 'rt' },
    el('div', {}, el('b', { text: r.title }), r.client_name ? el('span', { class: 'muted', text: ' · ' + r.client_name }) : null,
      el('div', { class: 'muted', style: 'font-size:12px', text: `${dstr(r.period_start)} → ${dstr(r.period_end)} · created ${fmtDate(r.created_at)}` })),
    el('div', { class: 'row' },
      el('button', { class: 'btn sm secondary', text: 'Open', onclick: async () => { const { report } = await api('/reports/' + r.id); gotoView('reports'); renderReportDetail(report); window.scrollTo(0, 9999); } }),
      el('button', { class: 'btn sm ghost', text: 'Exec PDF', onclick: () => downloadPdf('/reports/' + r.id + '/pdf?mode=executive', 'soc-exec-report.pdf') }))));
  body.appendChild(lst);
}

// ---------- reports ----------
async function generateReport(uploadId) {
  if (!uploadId) return toast('Select an upload first', 'err');
  try {
    const { report } = await api('/reports', { method: 'POST', body: { uploadId } });
    toast('Report generated');
    await loadReportsData();
    gotoView('reports');
    renderReportDetail(report);
    await renderOnboarding();
  } catch (e) { toast(e.message, 'err'); }
}
async function loadReportsData() { const { reports } = await api('/reports'); state._reports = reports; return reports; }
async function loadReports() {
  const reports = await loadReportsData();
  const wrap = $('#reportListWrap'); wrap.textContent = '';
  wrap.appendChild(el('h3', { text: 'Report history' }));
  if (!reports.length) { wrap.appendChild(el('div', { class: 'muted', text: 'No reports yet — generate one from the Dashboard.' })); $('#reportDetail').textContent = ''; return; }
  for (const r of reports) {
    const row = el('div', { class: 'rt' },
      el('div', {}, el('b', { text: r.title }), r.client_name ? el('span', { class: 'muted', text: ' · ' + r.client_name }) : null,
        el('div', { class: 'muted', style: 'font-size:12px', text: `${dstr(r.period_start)} → ${dstr(r.period_end)} · created ${fmtDate(r.created_at)}` })),
      el('div', { class: 'row' },
        el('button', { class: 'btn sm secondary', text: 'Open', onclick: async () => { const { report } = await api('/reports/' + r.id); renderReportDetail(report); window.scrollTo(0, 9999); } }),
        el('button', { class: 'btn sm ghost', text: 'PDF', onclick: () => downloadPdf('/reports/' + r.id + '/pdf', 'soc-report.pdf') }),
        can('analyst') ? el('button', { class: 'btn sm danger', text: 'Delete', onclick: async () => { if (confirm('Delete this report?')) { await api('/reports/' + r.id, { method: 'DELETE' }); toast('Deleted'); loadReports(); $('#reportDetail').textContent=''; } } }) : null));
    wrap.appendChild(row);
  }
}
function evidenceLine(ids) { return el('div', { class: 'evidence', text: 'Evidence event IDs: ' + ((ids && ids.length) ? ids.slice(0, 12).join(', ') : 'n/a') }); }

function renderReportDetail(report) {
  const d = report.data, ai = d.ai_analysis, m = d.mitre_attack;
  const box = $('#reportDetail'); box.textContent = '';

  box.appendChild(el('div', { class: 'card', style: 'margin-top:16px' },
    el('div', { class: 'row', style: 'justify-content:space-between;align-items:center' },
      el('div', {}, el('h2', { text: d.title + (d.client_name ? ' — ' + d.client_name : '') }),
        el('div', { class: 'muted', text: `${dstr(d.period_start)} → ${dstr(d.period_end)} · ${d.dashboard.totals.total} alerts` })),
      el('div', { class: 'row' },
        can('analyst') ? el('button', { class: 'btn secondary', text: '🔗 Share (Executive)', title: 'Management-safe link: hides raw logs, hostnames, users, event IDs', onclick: () => createShare(report.id, 'executive') }) : null,
        can('analyst') ? el('button', { class: 'btn secondary', text: '🔗 Share (Analyst)', title: 'Full technical detail — share only with trusted recipients', onclick: () => createShare(report.id, 'analyst') }) : null,
        el('button', { class: 'btn secondary', text: '⬇ Executive PDF', onclick: () => downloadPdf('/reports/' + report.id + '/pdf?mode=executive', 'soc-executive-report.pdf') }),
        el('button', { class: 'btn', text: '⬇ Analyst PDF', onclick: () => downloadPdf('/reports/' + report.id + '/pdf?mode=analyst', 'soc-analyst-report.pdf') }))),
    el('div', { id: 'shareArea', style: 'margin-top:12px' })));

  // Posture + comparison summary
  if (d.meta && d.meta.posture) box.appendChild(postureCard(d.meta.posture));
  if (d.comparison) {
    const c = d.comparison;
    box.appendChild(el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'Historical comparison' }),
      el('p', { class: 'muted', style: 'font-size:13px', text: c.available ? c.note : (c.note || 'Historical comparison unavailable.') })));
  }

  const aiCard = el('div', { class: 'card', style: 'margin-top:14px' },
    el('span', { class: 'badge', text: ai.label + ' · ' + ai.provider }),
    el('h3', { text: 'Analyst-assist summary' }), el('p', { text: ai.summary }),
    el('p', { class: 'muted', style: 'font-size:12px', text: ai.disclaimer }),
    el('h3', { text: 'Key observations' }));
  const ul = el('ul', {}); for (const o of ai.key_observations || []) ul.appendChild(el('li', { text: o })); aiCard.appendChild(ul);
  box.appendChild(aiCard);

  // Top security findings
  const fc = el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'Top security findings (evidence-cited)' }));
  if (!d.findings || !d.findings.length) fc.appendChild(el('p', { class: 'muted', text: 'No findings met the reporting threshold.' }));
  for (const f of (d.findings || [])) fc.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('b', { text: f.title }), ' ', el('span', { class: 'pill ' + barClass(f.severity), style: 'color:#fff', text: `${f.severity} · ${f.confidence}` })),
    el('div', { class: 'muted', style: 'font-size:12px', text: f.description }), evidenceLine(f.evidence && f.evidence.event_ids)));
  box.appendChild(fc);

  // Recommended actions (AI-assisted)
  const ract = el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'Recommended actions (management action plan)' }),
    el('p', { class: 'muted', style: 'font-size:12px', text: 'AI-assisted recommendations for a human analyst — not statements of fact.' }));
  if (!d.recommended_actions || !d.recommended_actions.length) ract.appendChild(el('p', { class: 'muted', text: 'No recommended actions.' }));
  for (const a of (d.recommended_actions || [])) ract.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('span', { class: 'pri pri-' + a.priority, text: a.priority }), ' ', el('b', { text: a.finding }), ' ', el('span', { class: 'aiflag', text: 'AI-assisted' })),
    el('div', { class: 'muted', style: 'font-size:12px', text: a.recommended_action + ' · Owner: ' + (a.owner || '—') }), evidenceLine(a.evidence && a.evidence.event_ids)));
  box.appendChild(ract);

  const rc = el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'Recurring patterns (evidence-cited)' }));
  if (!ai.recurring_patterns.length) rc.appendChild(el('p', { class: 'muted', text: 'No recurring pattern met threshold.' }));
  for (const p of ai.recurring_patterns) rc.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('b', { text: p.pattern }), ' ', el('span', { class: 'pill ' + barClass(p.severity), style: 'color:#fff', text: `${p.severity} · ${p.alert_count}` })),
    el('div', { class: 'muted', style: 'font-size:12px', text: p.rationale }), evidenceLine(p.evidence_event_ids)));
  box.appendChild(rc);

  const fp = el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'False-positive / tuning candidates' }),
    el('p', { class: 'muted', style: 'font-size:12px', text: 'Flagged for analyst review — candidates, NOT determinations.' }));
  if (!ai.false_positive_candidates.length) fp.appendChild(el('p', { class: 'muted', text: 'None flagged.' }));
  for (const f of ai.false_positive_candidates) fp.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('b', { text: f.rule })), el('div', { class: 'muted', style: 'font-size:12px', text: f.reason }), evidenceLine(f.evidence_event_ids)));
  box.appendChild(fp);

  const mc = el('div', { class: 'card', style: 'margin-top:14px' }, el('h3', { text: 'MITRE ATT&CK mapping (evidence-gated)' }));
  if (m.note) mc.appendChild(el('p', { class: 'muted', text: m.note }));
  for (const mp of m.mappings) mc.appendChild(el('div', { class: 'finding' },
    el('div', {}, el('b', { text: mp.technique_id + (mp.technique_name ? ' — ' + mp.technique_name : '') }), ' ',
      el('span', { class: 'muted', text: `${mp.alert_count} alerts · ${mp.confidence} · ${mp.evidence_source}` })), evidenceLine(mp.evidence_event_ids)));
  box.appendChild(mc);

  loadSharesInto(report.id);
}
async function downloadPdf(path, name) {
  try { const res = await api(path); const blob = await res.blob(); const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: name }); document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); }
  catch (e) { toast(e.message, 'err'); }
}
async function createShare(reportId, mode = 'executive') {
  if (mode === 'analyst' && !confirm('Analyst links expose FULL technical detail (raw logs, hostnames, usernames, event IDs). Share only with trusted recipients. Continue?')) return;
  const hours = prompt('Link valid for how many hours?', '168'); if (hours == null) return;
  try { const { share } = await api('/reports/' + reportId + '/shares', { method: 'POST', body: { expiresInHours: parseInt(hours, 10) || 168, mode } });
    await navigator.clipboard?.writeText(share.url).catch(() => {}); toast(`${share.mode === 'analyst' ? 'Analyst' : 'Executive'} share link created & copied`); loadSharesInto(reportId);
    const area = $('#shareArea'); if (area) { area.textContent = ''; area.appendChild(el('div', { class: 'finding' }, el('b', { text: `New ${share.mode} link (copy now): ` }), el('span', { class: 'evidence', text: share.url })));}
  } catch (e) { toast(e.message, 'err'); }
}
async function loadSharesInto(reportId) {
  try {
    const { shares } = await api('/reports/' + reportId + '/shares');
    const area = $('#shareArea'); if (!area) return;
    const existing = area.querySelector('#shareList'); if (existing) existing.remove();
    const list = el('div', { id: 'shareList' });
    if (shares.length) {
      list.appendChild(el('h3', { text: 'Active share links' }));
      for (const s of shares) list.appendChild(el('div', { class: 'rt' },
        el('div', {}, el('span', { class: 'badge', style: 'margin-right:6px', text: (s.mode || 'executive') === 'analyst' ? 'ANALYST' : 'EXECUTIVE' }), el('span', { class: 'evidence', text: `${s.token_prefix}… ` }),
          el('span', { class: 'muted', style: 'font-size:12px', text: `expires ${fmtDate(s.expires_at)} · ${s.view_count} views` + (s.revoked ? ' · REVOKED' : '') })),
        (!s.revoked && can('analyst')) ? el('button', { class: 'btn sm danger', text: 'Revoke', onclick: async () => { await api('/reports/' + reportId + '/shares/' + s.id, { method: 'DELETE' }); toast('Revoked'); loadSharesInto(reportId); } }) : null));
    }
    area.appendChild(list);
  } catch { /* ignore */ }
}

// ---------- schedule ----------
async function loadSchedules() {
  const { schedules } = await api('/schedules');
  const list = $('#schedList'); list.textContent = ''; $('#schedForm').textContent = '';
  list.appendChild(el('h3', { text: 'Schedules' }));
  if (!schedules.length) { list.appendChild(el('div', { class: 'muted', text: 'No schedules yet.' })); return; }
  for (const s of schedules) {
    list.appendChild(el('div', { class: 'rt' },
      el('div', {}, el('b', { text: s.name }), s.enabled ? el('span', { class: 'pill', style: 'background:#123a2a;color:#5be0a0', text: ' enabled' }) : el('span', { class: 'pill', style: 'background:#3a1b1b;color:#ffb4b4', text: ' paused' }),
        el('div', { class: 'muted', style: 'font-size:12px', text: `${DOW[s.day_of_week]} ${String(s.hour).padStart(2,'0')}:${String(s.minute).padStart(2,'0')} ${s.timezone} → ${(s.recipients||[]).join(', ') || 'no recipients'}` }),
        el('div', { class: 'muted', style: 'font-size:12px', text: `next run: ${fmtDate(s.next_run_at)}${s.last_status ? ' · last: ' + s.last_status : ''}` })),
      can('analyst') ? el('div', { class: 'row' },
        el('button', { class: 'btn sm secondary', text: 'Run now', onclick: async () => { try { const r = await api('/schedules/' + s.id + '/run', { method: 'POST' }); toast('Run: ' + r.status); loadSchedules(); } catch (e) { toast(e.message, 'err'); } } }),
        el('button', { class: 'btn sm ghost', text: s.enabled ? 'Pause' : 'Resume', onclick: async () => { await api('/schedules/' + s.id, { method: 'PUT', body: { enabled: !s.enabled } }); loadSchedules(); } }),
        el('button', { class: 'btn sm danger', text: 'Delete', onclick: async () => { if (confirm('Delete schedule?')) { await api('/schedules/' + s.id, { method: 'DELETE' }); loadSchedules(); } } })) : null));
  }
}
$('#newSchedBtn').addEventListener('click', () => {
  const f = $('#schedForm'); f.textContent = '';
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const daySel = el('select', {}); DOW.forEach((d, i) => daySel.appendChild(el('option', { value: String(i), text: d, selected: i === 1 ? '' : null })));
  const card = el('div', { class: 'card', style: 'margin-bottom:16px' }, el('h3', { text: 'New weekly schedule' }),
    el('label', { text: 'Name' }), el('input', { id: 'sfName', value: 'Weekly SOC Report' }),
    el('div', { class: 'row' },
      el('div', { class: 'split' }, el('label', { text: 'Day' }), daySel),
      el('div', { class: 'split' }, el('label', { text: 'Time (HH:MM)' }), el('input', { id: 'sfTime', type: 'time', value: '08:00' })),
      el('div', { class: 'split' }, el('label', { text: 'Timezone' }), el('input', { id: 'sfTz', value: tz }))),
    el('label', { text: 'Recipients (comma-separated emails)' }), el('input', { id: 'sfRcpt', placeholder: 'ciso@acme.com, soc@acme.com' }),
    el('label', { text: 'Client name (optional)' }), el('input', { id: 'sfClient', placeholder: 'Overrides default client' }),
    el('div', { style: 'margin-top:14px' }, el('button', { class: 'btn', text: 'Create schedule', onclick: async () => {
      const [hh, mm] = ($('#sfTime').value || '08:00').split(':');
      try {
        await api('/schedules', { method: 'POST', body: {
          name: $('#sfName').value, day_of_week: parseInt(daySel.value, 10), hour: parseInt(hh, 10), minute: parseInt(mm, 10),
          timezone: $('#sfTz').value, recipients: $('#sfRcpt').value.split(',').map((x) => x.trim()).filter(Boolean), client_name: $('#sfClient').value || null,
        }});
        toast('Schedule created'); loadSchedules();
      } catch (e) { toast(e.message, 'err'); }
    } })));
  f.appendChild(card);
});

// ---------- team ----------
async function loadTeam() {
  if (!can('admin')) { $('#memberList').textContent = ''; $('#memberList').appendChild(el('div', { class: 'muted', text: 'Admin only.' })); return; }
  const { members } = await api('/tenant/members');
  const list = $('#memberList'); list.textContent = ''; $('#memberForm').textContent = '';
  const body = el('tbody', {});
  for (const mem of members) {
    const roleSel = el('select', { style: 'width:130px', onchange: async (e) => { try { await api('/tenant/members/' + mem.id, { method: 'PUT', body: { role: e.target.value } }); toast('Role updated'); } catch (err) { toast(err.message, 'err'); loadTeam(); } } });
    ['admin', 'analyst', 'viewer'].forEach((r) => roleSel.appendChild(el('option', { value: r, text: r, selected: mem.role === r ? '' : null })));
    body.appendChild(el('tr', {},
      el('td', { text: mem.email + (mem.id === state.me.id ? ' (you)' : '') }),
      el('td', {}, roleSel),
      el('td', { class: 'muted', text: dstr(mem.created_at) }),
      el('td', {}, mem.id !== state.me.id ? el('button', { class: 'btn sm danger', text: 'Remove', onclick: async () => { if (confirm('Remove ' + mem.email + '?')) { await api('/tenant/members/' + mem.id, { method: 'DELETE' }); toast('Removed'); loadTeam(); } } }) : null)));
  }
  list.appendChild(el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'Email' }), el('th', { text: 'Role' }), el('th', { text: 'Added' }), el('th', {}))), body));
}
$('#newMemberBtn').addEventListener('click', () => {
  if (!can('admin')) return toast('Admin only', 'err');
  const f = $('#memberForm'); f.textContent = '';
  const roleSel = el('select', {}); ['viewer', 'analyst', 'admin'].forEach((r) => roleSel.appendChild(el('option', { value: r, text: r })));
  f.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px' }, el('h3', { text: 'Add team member' }),
    el('div', { class: 'row' },
      el('div', { class: 'split' }, el('label', { text: 'Email' }), el('input', { id: 'mEmail', type: 'email' })),
      el('div', { class: 'split' }, el('label', { text: 'Temp password' }), el('input', { id: 'mPass', type: 'text', value: 'changeme123' })),
      el('div', { class: 'split' }, el('label', { text: 'Role' }), roleSel)),
    el('div', { style: 'margin-top:14px' }, el('button', { class: 'btn', text: 'Create', onclick: async () => {
      try { await api('/tenant/members', { method: 'POST', body: { email: $('#mEmail').value.trim(), password: $('#mPass').value, role: roleSel.value } }); toast('Member added'); loadTeam(); }
      catch (e) { toast(e.message, 'err'); }
    } }))));
});

// ---------- settings ----------
async function loadSettings() {
  const { branding } = await api('/tenant/branding');
  $('#brandCompany').value = branding.company_name || '';
  $('#brandClient').value = branding.default_client || '';
  const prev = $('#logoPreview'); prev.textContent = '';
  if (branding.logo_data_url) prev.appendChild(el('img', { src: branding.logo_data_url, style: 'max-height:48px;border-radius:6px' }));
  const plan = await api('/tenant/plan');
  state.tenantPlan = plan.plan;
  const pb = $('#planBox'); pb.textContent = '';
  pb.appendChild(el('div', {}, el('span', { class: 'badge', text: 'Current: ' + plan.plan.toUpperCase() }),
    el('div', { class: 'muted', style: 'font-size:13px;margin-top:8px', text: `Seats used: ${plan.usage.members}/${plan.entitlements.maxTeamMembers} · Schedules: ${plan.usage.schedules}/${plan.entitlements.maxSchedules} · Sharing: ${plan.entitlements.sharing ? 'yes' : 'no'} · Branding: ${plan.entitlements.branding ? 'yes' : 'no'}` })));
  renderPricing($('#planCards'), { inApp: true });
  applyRoleVisibility();
}
let logoDataUrl = null;
$('#brandLogo').addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  if (file.size > 256 * 1024) return toast('Logo must be ≤256KB', 'err');
  const reader = new FileReader(); reader.onload = () => { logoDataUrl = reader.result; const prev = $('#logoPreview'); prev.textContent = ''; prev.appendChild(el('img', { src: logoDataUrl, style: 'max-height:48px;border-radius:6px' })); }; reader.readAsDataURL(file);
});
$('#saveBrandBtn').addEventListener('click', async () => {
  try { const body = { company_name: $('#brandCompany').value, default_client: $('#brandClient').value }; if (logoDataUrl) body.logo_data_url = logoDataUrl;
    await api('/tenant/branding', { method: 'PUT', body }); toast('Branding saved'); logoDataUrl = null; }
  catch (e) { toast(e.message, 'err'); }
});
async function changePlan(planId) {
  try { await api('/tenant/plan', { method: 'PUT', body: { plan: planId } }); toast('Plan changed to ' + planId); loadSettings(); }
  catch (e) { toast(e.message, 'err'); }
}
$('#purgeBtn').addEventListener('click', async () => {
  if (!confirm('This permanently deletes ALL uploads, reports and schedules for your org. Continue?')) return;
  try { await api('/tenant/data', { method: 'DELETE' }); toast('All data deleted'); state.uploadId = null; loadDashboard(); }
  catch (e) { toast(e.message, 'err'); }
});

// ---------- boot ----------
async function loadConfig() { try { state.cfg = await api('/config'); } catch { state.cfg = { plans: [], demoMode: false }; } }
async function boot() {
  await loadConfig();
  renderPricing($('#pricingCards'));
  try {
    state.me = await api('/auth/me');
    $('#who').textContent = `${state.me.email} · ${state.me.role} · ${state.me.tenant_name}`;
    showApp(); applyRoleVisibility();
    await refreshUploads();
    await loadReportsData();
    await renderOnboarding();
    gotoView('dashboard');
  } catch { showLanding(); }
}
boot();
