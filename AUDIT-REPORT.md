# SOC Report Copilot — Senior Security & Product Audit

**Scope:** Skeptical, senior-level review of the v2 "management-ready Wazuh SOC reporting" product across product correctness, security, report quality, production readiness, and commercial credibility. Critical/High issues were fixed with regression tests; Medium/Low issues are documented for planning. No redesign, no new integrations, no billing, no autonomous response were introduced.

**Date:** 2026-09-27
**Verdict:** **Solid, demonstrable product with an honest deterministic engine. Two High-severity correctness bugs were found and fixed. It is NOT yet production-ready** — see Remaining Limitations. Suitable for controlled pilots with a named analyst in the loop.

---

## 1. Method

- **Read-only code inspection** of auth, RBAC, tenant isolation, input sanitisation, error handling, sharing, scheduling, config, comparison, and PDF rendering.
- **Live adversarial probing** against a running instance (real Postgres + Node), including a throwaway tenant that was deleted afterwards.
- **Full automated suite** run before and after every change.

---

## 2. Findings by severity

### CRITICAL — none found
No authentication bypass, tenant-isolation break, injection, or unauthenticated data-exposure defect was found in live testing (see §4 for what was verified).

### HIGH — 2 found, **both fixed**

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| **H1** | **Historical comparison selected the "previous" report by generation time (`created_at DESC`), not by reporting period.** Uploading an older period after a newer one made the tool compare against a *future* period and report a **reversed, false trend** (a genuine improvement shown as "deteriorated" and vice-versa). Two reports covering the *same* period were also compared as if time had passed. | Management sees a trend arrow pointing the wrong way — directly undermines the "trend comparisons are mathematically correct / only claim change when data supports it" guarantee. | **FIXED** — previous is now the most recent report whose `period_end` is strictly earlier than the current report's period. Reports for the earliest period correctly say *"Historical comparison unavailable."* Regression tests added. |
| **H2** | **"New vs recurring activity" was mislabeled.** The numbers measure *in-dataset rule frequency* (a rule seen ≥3× = "recurring"; seen 1–2× = "new"), but the wording ("New / one-off activity") reads to a manager as **new since last week**. In the demo every rule fires ≥3×, so "new = 0" — misleading. | An executive misreads the report's most attention-grabbing line. Report-quality / trustworthiness issue. | **FIXED** — relabeled everywhere (PDF, exec dashboard, exec summary) to "Repeated activity (rule fired 3+ times)" and "Lower-frequency activity (seen 1–2 times)", with an explicit note that this is in-dataset frequency, **not** novelty. True cross-period novelty is surfaced separately via the Historical Comparison "newly appearing categories" delta. Regression test added. |

### MEDIUM — documented, not fixed (see rationale)

| ID | Finding | Recommendation |
|----|---------|----------------|
| **M1** | **Scheduled "weekly" reporting is cadence-only, not windowed.** The scheduler builds each report over the *entire* upload (min→max event timestamp), not a rolling 7-day window, and has no duplicate-run guard. In the intended workflow (upload this week's export → get this week's report) output is correct; but accumulating months in one upload and expecting auto-windowed weeklies will not work, and repeated ticks with no new upload can create duplicate reports. | Define window semantics (rolling N days vs since-last-report), scope the query by period, and skip a run when no new events exist since the last scheduled report. Deferred to avoid producing empty demo reports and scope creep; the H1 fix already removes the false-trend symptom of same-period regeneration. |
| **M2** | **Public share links expose full analyst detail** (raw logs, internal hostnames, users, source IPs) via both the JSON view and the PDF (which defaults to analyst mode). Acceptable when the recipient is the data owner; risky if a link is forwarded to a third party. | Add an "executive-only" share option and default shared PDFs to executive mode. Links are already sha256-hashed, expiring, revocable, and rate-limited. |
| **M3** | **Data retention advertised but not enforced.** Plans define `retentionDays` (30/180/730) but nothing purges old data — a commercial-credibility gap if the pricing page implies enforced retention. | Implement a retention sweep job, or remove the claim until it exists. |
| **M4** | **`corsOrigin` defaults to `*`.** Lower risk because the API uses Bearer tokens, not cookies, but still permissive. | Set an explicit allowlist in production config. |
| **M5** | **Finding/action counts on the executive dashboard are tenant-wide, while alert totals are per-upload.** Defensible (management cares about all open items) but inconsistent within one view. | Clarify labelling or scope both to the selected report. |

### LOW
- Login rate limit (50 / 15 min) is generous; consider tightening.
- No first-run empty states / onboarding copy in the SPA.

---

## 3. Fixes implemented this pass

- `backend/src/services/report/builder.js` — comparison now selects the chronologically previous report by `period_end` (H1).
- `backend/src/services/report/pdf.js` — corrected alert-frequency wording + clarifying note (H2).
- `backend/public/app.js`, `backend/src/services/report/builder.js` — corrected exec-dashboard / exec-summary labels (H2).
- `backend/tests/comparison_ordering.test.js` — **NEW** 3 regression tests (out-of-order selection, in-order trend, cross-period novelty).
- `backend/tests/dashboard_v2.test.js` — two existing comparison tests updated to use chronologically distinct periods (they previously encoded the buggy same-period assumption).
- Docs (`README.md`, `DESIGN.md`) — test count updated to 63.

**Test result after fixes:** `# tests 63 · # pass 63 · # fail 0`.

Sample deliverables regenerated with corrected labels: `sample-executive-report.pdf` (4 pp), `sample-analyst-report.pdf` (14 pp) — no blank pages, correct page numbering, branding applied.

---

## 4. Verified solid (no change needed)

- **AuthN:** JWT; tenant derived from token only (never from client input); signup/login rate-limited.
- **AuthZ / RBAC:** role hierarchy enforced on protected routes.
- **Tenant isolation:** live-tested — cross-tenant report access by valid UUID returns **404**; a fresh tenant sees 0 actions and `has_data:false`.
- **Injection / traversal:** `mode` query param is whitelisted (junk, `../../etc/passwd`, null bytes, `'; DROP TABLE …` all fall back to analyst mode, HTTP 200, no traversal, no SQLi, no header injection); SQL is parameterised throughout.
- **Oversized input:** a 200 KB rule description / 5 KB host field is truncated to 512 chars server-side; PDF renders cleanly with no overflow or crash.
- **Untrusted log content:** stored and rendered as inert text (no `innerHTML`/`eval`; `share.html` uses `textContent`); XSS-in-PDF covered by tests.
- **Error handling:** 500s hide internals; no stack traces leaked.
- **AI safety:** deterministic engine is the default; every finding cites real event IDs; MITRE is evidence-gated ("Not enough evidence." otherwise); recommendations labelled "AI-assisted recommendation," not fact.

---

## 5. Remaining production risks

1. **Scheduling is not true windowed weekly reporting** (M1) — set expectations or implement before selling "automated weekly reports."
2. **No data-retention / lifecycle enforcement, no backups, no down-migrations** (M3) — required before handling real customer telemetry.
3. **Share-link exposure default** (M2) — tighten before links are shared outside the data owner.
4. **Operational fragility observed in this environment:** dependencies (`node_modules`) and Postgres runtime dirs are not persisted across snapshots and had to be restored; there is no health-check-driven restart or documented DB bootstrap for a fresh host. Harden deployment (containerise, pin the DB bootstrap, add a supervisor/health check) before production.
5. **CORS `*` default** (M4).

---

## 6. Recommended next step

Ship to a **time-boxed pilot with one friendly MSSP client and a named analyst in the loop**, explicitly scoped to the "upload weekly export → generate report" workflow (which works correctly today). In parallel, close M1 (windowed scheduling) and M3 (retention + backups), which are the two gaps that most directly block a paid production claim. Do **not** market "automated weekly reporting" or enforced retention until those land.
