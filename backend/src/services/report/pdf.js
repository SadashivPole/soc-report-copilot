'use strict';
const PDFDocument = require('pdfkit');

/**
 * Render a report object to a PDF stream in a professional MSSP layout.
 *
 * SECURITY: all uploaded/derived values are drawn as TEXT (or as a bounded,
 * format-validated image for the logo) via pdfkit — there is no HTML/JS
 * execution path, so malicious log content cannot execute or render as markup.
 *
 * @param report the report `data` object produced by builder.buildReport
 * @param stream writable output stream
 * @param opts   { mode: 'executive' | 'analyst' }  (default 'analyst')
 */
function renderReportPdf(report, stream, opts = {}) {
  const mode = opts.mode === 'executive' ? 'executive' : 'analyst';
  const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true });
  doc.pipe(stream);

  const C = {
    navy: '#0f2038',
    ink: '#111827',
    body: '#374151',
    muted: '#6b7280',
    accent: '#1d4ed8',
    accent2: '#0ea5e9',
    line: '#e5e7eb',
    panel: '#f4f6fb',
    panel2: '#eef2ff',
    Critical: '#b91c1c',
    High: '#c2410c',
    Medium: '#a16207',
    Low: '#15803d',
    good: '#15803d',
    bad: '#b91c1c',
    warn: '#a16207',
    white: '#ffffff',
  };
  const POSTURE_COLOR = { critical: C.Critical, elevated: C.High, guarded: C.Medium, stable: C.Low };
  const ML = doc.page.margins.left;
  const W = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const BOTTOM = () => doc.page.height - doc.page.margins.bottom;

  const meta = report.meta || {};
  const brand = report.branding || {};
  const company = meta.organization || brand.company_name || null;
  const client = meta.client_name || report.client_name || null;

  const fmtDate = (d) => (d ? new Date(d).toISOString().slice(0, 10) : 'n/a');
  const fmtDateTime = (d) => {
    try {
      return new Date(d).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    } catch {
      return 'n/a';
    }
  };
  const periodLabel =
    meta.period_label ||
    (report.period_start && report.period_end
      ? `${fmtDate(report.period_start)}  to  ${fmtDate(report.period_end)}`
      : 'n/a');

  // ---- primitives ----
  function ensureSpace(min) {
    if (doc.y + min > BOTTOM()) doc.addPage();
  }
  const body = (t, o = {}) => {
    doc
      .fillColor(o.color || C.body)
      .font(o.font || 'Helvetica')
      .fontSize(o.size || 10);
    // Always reset to the left margin / full width so absolute-positioned
    // primitives (KPI cards, charts, tables) never leave x stranded mid-page.
    return doc.text(t, o.x != null ? o.x : ML, doc.y, { width: o.width || W, align: o.align, continued: o.continued });
  };
  const muted = (t, o = {}) => body(t, { color: C.muted, size: 8.5, ...o });

  let sectionNo = 0;
  function section(title) {
    ensureSpace(70);
    sectionNo += 1;
    doc.moveDown(0.6);
    doc
      .fillColor(C.navy)
      .font('Helvetica-Bold')
      .fontSize(13.5)
      .text(`${sectionNo}. ${title}`, ML, doc.y);
    doc
      .moveTo(ML, doc.y + 3)
      .lineTo(ML + W, doc.y + 3)
      .strokeColor(C.accent)
      .lineWidth(1.5)
      .stroke();
    doc.moveDown(0.6);
    doc.fillColor(C.body);
  }
  function subhead(t) {
    ensureSpace(28);
    doc.moveDown(0.2).fillColor(C.ink).font('Helvetica-Bold').fontSize(10.5).text(t, ML, doc.y);
    doc.moveDown(0.2).fillColor(C.body);
  }
  function bullet(t, o = {}) {
    ensureSpace(20);
    body(`•  ${t}`, { size: o.size || 9.5, color: o.color || C.body });
  }
  function note(t) {
    ensureSpace(30);
    const h = doc.heightOfString(t, { width: W - 16, fontSize: 9 }) + 12;
    doc.roundedRect(ML, doc.y, W, h, 4).fill(C.panel2);
    doc.fillColor(C.accent).font('Helvetica').fontSize(9).text(t, ML + 8, doc.y + 6, { width: W - 16 });
    doc.y += 6;
    doc.moveDown(0.4);
    doc.fillColor(C.body);
  }

  // Wrapping, paginating table. columns: [{label,width,align,color}]
  function table(columns, rows, o = {}) {
    const size = o.size || 8.5;
    const pad = 5;
    const headerH = 20;
    const sum = columns.reduce((a, c) => a + c.width, 0);
    const px = columns.map((c) => Math.floor((c.width / sum) * W));
    const drawHeader = () => {
      doc.rect(ML, doc.y, W, headerH).fill(C.navy);
      let x = ML;
      const y = doc.y;
      doc.fillColor(C.white).font('Helvetica-Bold').fontSize(size);
      columns.forEach((c, i) => {
        doc.text(c.label, x + pad, y + 6, { width: px[i] - 2 * pad, align: c.align || 'left', lineBreak: false, ellipsis: true });
        x += px[i];
      });
      doc.y = y + headerH;
    };
    if (!rows.length) {
      muted('  (none)');
      return;
    }
    ensureSpace(headerH + 26);
    drawHeader();
    let zebra = false;
    for (const row of rows) {
      doc.font('Helvetica').fontSize(size);
      let h = 0;
      row.forEach((cell, i) => {
        const hh = doc.heightOfString(String(cell == null ? '' : cell), { width: px[i] - 2 * pad });
        if (hh > h) h = hh;
      });
      h = Math.max(h + 2 * pad, 16);
      if (doc.y + h > BOTTOM() - 24) {
        doc.addPage();
        drawHeader();
        zebra = false;
      }
      const rowY = doc.y;
      if (zebra) doc.rect(ML, rowY, W, h).fill(C.panel);
      let x = ML;
      columns.forEach((c, i) => {
        const val = String(row[i] == null ? '' : row[i]);
        doc
          .fillColor(c.color ? c.color(row[i]) : C.body)
          .font(c.bold ? 'Helvetica-Bold' : 'Helvetica')
          .fontSize(size)
          .text(val, x + pad, rowY + pad, { width: px[i] - 2 * pad, align: c.align || 'left' });
        x += px[i];
      });
      doc.y = rowY + h;
      doc.moveTo(ML, doc.y).lineTo(ML + W, doc.y).strokeColor(C.line).lineWidth(0.5).stroke();
      zebra = !zebra;
    }
    doc.moveDown(0.5);
    doc.fillColor(C.body);
  }

  const sevColor = (s) => C[s] || C.body;

  // KPI cards row.
  function kpiCards(cards) {
    ensureSpace(64);
    const gap = 8;
    const n = cards.length;
    const cw = (W - gap * (n - 1)) / n;
    const y = doc.y;
    cards.forEach((c, i) => {
      const x = ML + i * (cw + gap);
      doc.roundedRect(x, y, cw, 52, 5).fill(c.bg || C.panel);
      doc.fillColor(c.fg || C.navy).font('Helvetica-Bold').fontSize(18).text(String(c.value), x, y + 8, { width: cw, align: 'center' });
      doc.fillColor(c.labelColor || C.muted).font('Helvetica').fontSize(7.5).text(c.label, x, y + 33, { width: cw, align: 'center' });
    });
    doc.y = y + 52;
    doc.moveDown(0.6);
    doc.fillColor(C.body);
  }

  // Horizontal severity distribution bar.
  function severityBar(sev) {
    const total = (sev.Critical || 0) + (sev.High || 0) + (sev.Medium || 0) + (sev.Low || 0) || 1;
    ensureSpace(40);
    const y = doc.y;
    const barH = 16;
    let x = ML;
    for (const level of ['Critical', 'High', 'Medium', 'Low']) {
      const wseg = (W * (sev[level] || 0)) / total;
      if (wseg > 0) {
        doc.rect(x, y, wseg, barH).fill(C[level]);
        if (wseg > 34) doc.fillColor(C.white).font('Helvetica-Bold').fontSize(8).text(String(sev[level]), x, y + 4, { width: wseg, align: 'center' });
        x += wseg;
      }
    }
    doc.y = y + barH + 4;
    // legend
    let lx = ML;
    for (const level of ['Critical', 'High', 'Medium', 'Low']) {
      doc.rect(lx, doc.y + 1, 8, 8).fill(C[level]);
      doc.fillColor(C.muted).font('Helvetica').fontSize(8).text(`${level} (${sev[level] || 0})`, lx + 11, doc.y, { lineBreak: false });
      lx += 90;
    }
    doc.y += 16;
    doc.fillColor(C.body);
  }

  // Simple ASCII-free trend chart (vertical bars).
  function trendChart(trend) {
    if (!trend || !trend.length) {
      muted('  (no timestamped events to chart)');
      return;
    }
    const data = trend.slice(-14);
    const max = Math.max(...data.map((t) => t.count), 1);
    const chartH = 70;
    ensureSpace(chartH + 30);
    const y0 = doc.y;
    const slot = W / data.length;
    const bw = Math.min(slot - 4, 26);
    data.forEach((t, i) => {
      const bh = Math.max(2, Math.round((t.count / max) * chartH));
      const x = ML + i * slot + (slot - bw) / 2;
      const y = y0 + chartH - bh;
      doc.rect(x, y, bw, bh).fill(C.accent);
      doc.fillColor(C.muted).font('Helvetica').fontSize(6).text(String(t.count), x - 2, y - 8, { width: bw + 4, align: 'center' });
      doc.fillColor(C.muted).fontSize(5.5).text(String(t.day).slice(5), x - 4, y0 + chartH + 2, { width: bw + 8, align: 'center' });
    });
    doc.y = y0 + chartH + 14;
    doc.fillColor(C.body);
  }

  // ======================================================================
  // COVER PAGE
  // ======================================================================
  const posture = meta.posture || (report.security_posture && report.security_posture.posture) || {};
  const pColor = POSTURE_COLOR[posture.level] || C.accent;

  doc.rect(0, 0, doc.page.width, 150).fill(C.navy);
  // logo
  if (brand.logo_data_url && typeof brand.logo_data_url === 'string') {
    const m = brand.logo_data_url.match(/^data:image\/(png|jpe?g);base64,([A-Za-z0-9+/=]+)$/);
    if (m) {
      try {
        const buf = Buffer.from(m[2], 'base64');
        if (buf.length > 0 && buf.length < 512 * 1024) doc.image(buf, ML, 40, { fit: [140, 70] });
      } catch {
        /* ignore bad logo */
      }
    }
  }
  doc.fillColor(C.white).font('Helvetica-Bold').fontSize(11).text(company || 'SOC Report Copilot', ML, 110, { width: W, align: 'right' });

  doc.fillColor(C.ink).font('Helvetica-Bold').fontSize(30).text(meta.title || report.title || 'Weekly SOC Report', ML, 220, { width: W });
  doc.fillColor(C.muted).font('Helvetica').fontSize(12).text(
    mode === 'executive' ? 'Executive Report — Management Summary' : 'Analyst Report — Detailed Technical Findings',
    { width: W }
  );
  doc.moveDown(1.5);

  const coverRow = (k, v) => {
    doc.fillColor(C.muted).font('Helvetica-Bold').fontSize(10).text(k, ML, doc.y, { continued: true, width: W });
    doc.fillColor(C.ink).font('Helvetica').text(`   ${v}`);
    doc.moveDown(0.3);
  };
  doc.moveDown(0.5);
  if (client) coverRow('Prepared for:', client);
  if (company) coverRow('Prepared by:', company);
  coverRow('Data source:', `${(meta.source_type || 'wazuh').toUpperCase()}${meta.filename ? '  (' + meta.filename + ')' : ''}`);
  coverRow('Reporting period:', periodLabel);
  coverRow('Generated:', fmtDateTime(meta.generated_at || report.generated_at));

  // Posture badge
  doc.moveDown(1);
  const badgeY = doc.y;
  doc.roundedRect(ML, badgeY, W, 60, 6).fill(C.panel);
  doc.roundedRect(ML, badgeY, 8, 60, 3).fill(pColor);
  doc.fillColor(C.muted).font('Helvetica-Bold').fontSize(9).text('OVERALL SECURITY POSTURE', ML + 20, badgeY + 10);
  doc.fillColor(pColor).font('Helvetica-Bold').fontSize(18).text(posture.label || 'Not determined', ML + 20, badgeY + 24);
  doc.y = badgeY + 68;
  if (posture.rationale) muted(posture.rationale, { width: W });

  doc.moveDown(2);
  doc.fillColor(C.muted).font('Helvetica-Oblique').fontSize(8).text(
    'CONFIDENTIAL — This report is generated automatically from uploaded security telemetry. ' +
      'AI-assisted content is evidence-bound: every finding cites underlying event IDs. Recommended actions are ' +
      'recommendations for a human analyst, not statements of fact or automated changes.',
    ML,
    BOTTOM() - 40,
    { width: W, align: 'center' }
  );

  doc.addPage();

  // ======================================================================
  // 1. EXECUTIVE SUMMARY
  // ======================================================================
  const es = report.executive_summary || {};
  const k = report.kpis || {};
  section('Executive Summary');
  kpiCards([
    { value: k.total || 0, label: 'TOTAL ALERTS' },
    { value: k.critical || 0, label: 'CRITICAL', fg: C.Critical },
    { value: k.high || 0, label: 'HIGH', fg: C.High },
    { value: (k.findings != null ? k.findings : 0), label: 'KEY FINDINGS', fg: C.accent },
    { value: (report.recommended_actions || []).length, label: 'ACTIONS' },
  ]);
  body(es.headline || (report.ai_analysis && report.ai_analysis.summary) || '', { size: 10 });
  doc.moveDown(0.4);
  subhead('What management should know');
  for (const o of (es.major_observations || []).slice(0, 5)) bullet(o, { size: 9.5 });

  // ======================================================================
  // 2. SECURITY POSTURE
  // ======================================================================
  const sp = report.security_posture || {};
  section('Security Posture');
  subhead('Severity distribution');
  severityBar(sp.severity || {});
  doc.moveDown(0.3);
  subhead('Alert activity');
  bullet(`Repeated activity: ${sp.recurring_alerts || 0} alerts belong to rule signatures that fired 3 or more times in this dataset.`);
  bullet(`Lower-frequency activity: ${sp.new_alerts || 0} alerts from rule signatures seen only once or twice in this dataset. (This reflects in-dataset frequency, not novelty versus a prior report — see Historical Comparison for newly appearing categories.)`);
  doc.moveDown(0.3);
  subhead('Daily alert trend');
  trendChart(sp.trend);

  // ======================================================================
  // HISTORICAL COMPARISON
  // ======================================================================
  const cmp = report.comparison || {};
  section('Historical Comparison');
  if (!cmp.available) {
    note(cmp.note || 'Historical comparison unavailable.');
  } else {
    note(cmp.note);
    table(
      [
        { label: 'Metric', width: 34 },
        { label: 'Previous', width: 22, align: 'right' },
        { label: 'Current', width: 22, align: 'right' },
        { label: 'Change', width: 22, align: 'right' },
      ],
      [
        ['Total alert volume', cmp.alert_volume.previous, cmp.alert_volume.current, `${cmp.alert_volume.delta >= 0 ? '+' : ''}${cmp.alert_volume.delta} (${cmp.alert_volume.direction})`],
        ['Critical', cmp.severity.previous.Critical, cmp.severity.current.Critical, cmp.severity.current.Critical - cmp.severity.previous.Critical],
        ['High', cmp.severity.previous.High, cmp.severity.current.High, cmp.severity.current.High - cmp.severity.previous.High],
        ['High + Critical', cmp.severity.previous.Critical + cmp.severity.previous.High, cmp.severity.current.Critical + cmp.severity.current.High, `${cmp.severity.high_critical_delta >= 0 ? '+' : ''}${cmp.severity.high_critical_delta} (${cmp.severity.direction})`],
      ]
    );
    const listDelta = (label, d) => {
      if (!d) return;
      if (d.added.length) bullet(`${label} newly appearing: ${d.added.slice(0, 6).join(', ')}`, { size: 9 });
      if (d.removed.length) bullet(`${label} no longer present: ${d.removed.slice(0, 6).join(', ')}`, { size: 9 });
    };
    subhead('Changes in indicators');
    listDelta('Categories', cmp.top_categories);
    listDelta('Recurring source IPs', cmp.recurring_source_ips);
    listDelta('MITRE techniques', cmp.mitre_techniques);
  }

  // ======================================================================
  // 3. ALERT & INCIDENT ANALYSIS
  // ======================================================================
  const an = report.analysis_section || {};
  section('Alert & Incident Analysis');
  const topLimit = mode === 'executive' ? 5 : 10;
  const toRows = (list) => (list || []).slice(0, topLimit).map((r) => [r.key, r.count]);
  const twoCols = [
    { label: 'Value', width: 78 },
    { label: 'Alerts', width: 22, align: 'right' },
  ];
  subhead('Top alert types');
  table(twoCols, toRows(an.top_alert_types));
  subhead('Top source IPs');
  table(twoCols, toRows(an.top_source_ips));
  subhead('Top affected hosts');
  table(twoCols, toRows(an.top_hosts));
  if (mode === 'analyst') {
    subhead('Top affected users');
    table(twoCols, toRows(an.top_users));
  }

  // ======================================================================
  // 4. TOP SECURITY FINDINGS
  // ======================================================================
  section('Top Security Findings');
  const findings = report.findings || [];
  if (!findings.length) {
    note('No correlated security findings met the reporting threshold in this window.');
  } else if (mode === 'executive') {
    table(
      [
        { label: 'Finding', width: 62 },
        { label: 'Severity', width: 18, color: (v) => sevColor(v), bold: true },
        { label: 'Confidence', width: 20 },
      ],
      findings.map((f) => [f.title, f.severity, f.confidence])
    );
  } else {
    findings.forEach((f, i) => {
      ensureSpace(90);
      doc.fillColor(C.ink).font('Helvetica-Bold').fontSize(10.5).text(`Finding ${i + 1}: ${f.title}`, ML, doc.y, { width: W });
      doc.moveDown(0.15);
      doc.fillColor(sevColor(f.severity)).font('Helvetica-Bold').fontSize(9).text(`Severity: ${f.severity}`, { continued: true });
      doc.fillColor(C.muted).font('Helvetica').text(`     Confidence: ${f.confidence}     Category: ${f.category}`);
      doc.moveDown(0.2);
      body(f.description, { size: 9.5 });
      const ev = f.evidence || {};
      muted(`Affected assets: ${(ev.assets || []).join(', ') || 'n/a'}`);
      muted(`Time span: ${fmtDateTime(ev.first_seen)}  ->  ${fmtDateTime(ev.last_seen)}`);
      muted(`Evidence event IDs: ${(ev.event_ids || []).slice(0, 15).join(', ') || 'n/a'}`);
      doc.moveDown(0.3);
      doc.moveTo(ML, doc.y).lineTo(ML + W, doc.y).strokeColor(C.line).lineWidth(0.5).stroke();
      doc.moveDown(0.3);
    });
  }

  // ======================================================================
  // 5. RECURRING PATTERNS
  // ======================================================================
  section('Recurring Patterns');
  const rps = report.recurring_patterns || [];
  if (mode === 'executive') {
    if (!rps.length) muted('No recurring multi-alert pattern met the reporting threshold.');
    else for (const rp of rps.slice(0, 5)) bullet(`${rp.pattern} — ${rp.alert_count} alerts [${rp.severity}]`, { size: 9.5 });
  } else {
    if (!rps.length) note('No recurring multi-alert pattern met the reporting threshold.');
    else
      table(
        [
          { label: 'Pattern', width: 52 },
          { label: 'Sev', width: 12, color: (v) => sevColor(v), bold: true },
          { label: 'Count', width: 10, align: 'right' },
          { label: 'Evidence event IDs', width: 26 },
        ],
        rps.map((rp) => [rp.pattern, rp.severity, rp.alert_count, (rp.evidence_event_ids || []).slice(0, 8).join(', ')])
      );
  }

  // ======================================================================
  // 6. FALSE-POSITIVE CANDIDATES
  // ======================================================================
  section('False-Positive / Tuning Candidates');
  note('Flagged for analyst review — these are CANDIDATES, not determinations. Analyst validation required.');
  const fps = report.false_positive_candidates || [];
  if (mode === 'executive') {
    body(`${fps.length} high-volume low/medium-severity rule(s) flagged for tuning review.`, { size: 9.5 });
  } else if (!fps.length) {
    muted('None flagged.');
  } else {
    table(
      [
        { label: 'Rule', width: 40 },
        { label: 'Sev', width: 10, color: (v) => sevColor(v), bold: true },
        { label: 'Count', width: 9, align: 'right' },
        { label: '% total', width: 10, align: 'right' },
        { label: 'Reason / evidence', width: 31 },
      ],
      fps.map((fp) => [
        fp.rule,
        fp.severity,
        fp.alert_count,
        `${(fp.share_of_total * 100).toFixed(1)}%`,
        `${fp.reason} Evidence: ${(fp.evidence_event_ids || []).slice(0, 5).join(', ')}`,
      ])
    );
  }

  // ======================================================================
  // 7. MITRE ATT&CK MAPPING
  // ======================================================================
  section('MITRE ATT&CK Mapping');
  const mit = report.mitre_section || report.mitre_attack || {};
  if (mit.note) {
    note(mit.note);
  } else {
    const rows = (mit.mappings || []).map((m) => [
      m.tactic || 'n/a',
      m.technique_name || 'n/a',
      m.technique_id,
      m.confidence,
      mode === 'analyst' ? (m.evidence_event_ids || []).slice(0, 8).join(', ') : String(m.alert_count),
    ]);
    table(
      [
        { label: 'Tactic', width: 22 },
        { label: 'Technique', width: 30 },
        { label: 'ID', width: 14 },
        { label: 'Confidence', width: 14 },
        { label: mode === 'analyst' ? 'Evidence event IDs' : 'Alerts', width: 20, align: mode === 'analyst' ? 'left' : 'right' },
      ],
      rows
    );
  }

  // ======================================================================
  // 8. RECOMMENDED ACTIONS
  // ======================================================================
  section('Recommended Actions (Management Action Plan)');
  note('AI-assisted recommendations for a human analyst — not statements of fact and not automated changes.');
  const ras = report.recommended_actions || [];
  if (!ras.length) {
    muted('No recommended actions generated.');
  } else {
    table(
      [
        { label: 'Pri', width: 8, bold: true },
        { label: 'Finding', width: 30 },
        { label: 'Recommended action', width: 40 },
        { label: 'Owner', width: 14 },
        { label: 'Status', width: 8 },
      ],
      ras.map((r) => [r.priority, r.finding, r.recommended_action, r.owner, (r.status || 'open').replace('_', ' ')])
    );
    if (mode === 'analyst') {
      subhead('Action evidence references');
      for (const r of ras) muted(`${r.priority} · ${r.finding} -> event IDs: ${(r.evidence.event_ids || []).slice(0, 10).join(', ') || 'n/a'}`);
    }
  }

  // ======================================================================
  // 9. EVIDENCE APPENDIX (analyst mode only)
  // ======================================================================
  if (mode === 'analyst') {
    section('Evidence Appendix');
    muted('Representative raw events (most severe first). Original log content is shown as text only.');
    doc.moveDown(0.2);
    const appx = report.evidence_appendix || [];
    if (!appx.length) muted('No events available.');
    else
      table(
        [
          { label: 'Event ID', width: 12 },
          { label: 'Timestamp', width: 15 },
          { label: 'Sev', width: 8, color: (v) => sevColor(v), bold: true },
          { label: 'Host', width: 12 },
          { label: 'User', width: 10 },
          { label: 'Rule / original evidence', width: 43 },
        ],
        appx.map((e) => [
          e.event_id,
          e.timestamp ? fmtDateTime(e.timestamp) : 'n/a',
          e.severity || '',
          e.host || '',
          e.user || '',
          `${e.rule || ''}${e.evidence ? '  |  ' + e.evidence : ''}`,
        ]),
        { size: 7.5 }
      );
  }

  // ======================================================================
  // FOOTER (page numbers + branding + generated timestamp) on every page
  // ======================================================================
  const range = doc.bufferedPageRange();
  const genStr = fmtDateTime(meta.generated_at || report.generated_at);
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(i);
    // Writing below the bottom margin would make pdfkit auto-insert a blank
    // page; zero this page's bottom margin so the footer stays on the page.
    doc.page.margins.bottom = 0;
    doc
      .fillColor(C.muted)
      .font('Helvetica')
      .fontSize(7.5)
      .text(
        `${company ? company + '  ·  ' : ''}${mode === 'executive' ? 'Executive' : 'Analyst'} Report  ·  Generated ${genStr}  ·  AI-assisted, evidence-bound  ·  Page ${i + 1} of ${range.count}`,
        ML,
        doc.page.height - 32,
        { width: W, align: 'center' }
      );
  }

  doc.end();
}

module.exports = { renderReportPdf };
