# SOC Report Copilot — Production-Hardening Report

**Date:** 2026-09-27
**Scope:** Remediation of the 10 items raised in `AUDIT-REPORT.md` (H1/H2 already closed).
**Constraints honoured:** No app rebuild, no new SIEM connectors, no autonomous response,
no live billing, no redesign of unrelated parts. Deterministic evidence engine remains the
default; AI prose stays optional and evidence-bound.

---

## 1. Executive Summary

All ten hardening items were implemented, tested, and verified end-to-end against a live
Postgres-backed instance. The full automated test suite is **86/86 passing** (baseline was 63),
with regression and adversarial coverage added for every fix. A complete live E2E — tenant
signup → upload → report → executive share (analyst content hidden) → scheduled weekly window →
duplicate prevention → prior-period comparison → retention enforcement → audit verification →
PDF export → **service restart with data persistence and healthcheck** — was executed and passed.

**Verdict:** No outstanding major data-loss, authorization, scheduling, or retention defects were
found in verification. See **§7 Remaining Risks & Limitations** for the honest caveats (chiefly:
Docker/compose changes were validated by config review + local Postgres, not by running the Docker
daemon, which is unavailable in this environment; and DB backups are operator-provisioned, not
enforced by the app).

---

## 2. Issues Fixed (mapped to audit items)

| # | Item | Status | What was wrong → what it does now |
|---|------|--------|-----------------------------------|
| M1 | True weekly windowing | ✅ Fixed | Scheduled reports analysed the **entire historical upload**. Now each scheduled run computes an explicit window (default: previous completed 7‑day period), stores `period_start`/`period_end`, analyses only in-window events, dedups per tenant+window, skips empty windows, and records every attempt in `schedule_runs`. Manual vs scheduled distinguished via `report_kind`. Chronological comparison preserved. |
| M2 | Safe sharing | ✅ Fixed | Public shares could expose analyst-level detail. Now shares carry a `mode` (`EXECUTIVE` default / `ANALYST` explicit). Executive JSON is whitelisted **and IOC-redacted**; executive PDF renders from a **deep-redacted clone**. Analyst detail requires explicit opt-in (with UI confirm). Token hashing, expiry, revocation, rate-limit preserved; create/access/revoke/expire audited in `share_audit`. |
| M3 | Retention + backups | ✅ Fixed (enforced portion) | No retention enforcement existed. Now a per-plan retention policy (`free=30 / pro=180 / mssp=730` days) deletes over-age uploads+events (and over-age reports), **preserves accountability records** (actions, `schedule_runs`, `share_audit`, `retention_runs`, `billing_events`), runs on a scheduled sweep + on-demand endpoint, is tenant-scoped, and logs each run to `retention_runs`. Backup/restore expectations documented (operator-owned) — **not falsely claimed as enforced**. |
| — | DB / bootstrap reliability | ✅ Fixed | Added PG healthcheck + API healthcheck, startup DB-readiness gate (`waitForDb`), fail-safe behaviour when PG is down, persistent named volume, restart policies, service-dependency ordering, and env validation with clear startup errors. |
| M4 | CORS | ✅ Fixed | Wildcard/implicit CORS. Now explicit allow-list from config; dev permits localhost; **prod refuses to boot** on wildcard/empty CORS; unexpected origins rejected; documented in `.env.example`. |
| M5 | Dashboard scope | ✅ Fixed | KPI numbers were ambiguous. Dashboard now separates **"Current Upload"** (this data source) from **"All Open Actions"** (tenant-wide), each with an explicit badge + caption; selecting a report shows which metrics belong to it. |
| — | Onboarding | ✅ Fixed | Added a first-run flow (create org/client → upload → validate events → generate report → view executive summary) plus useful empty states. No superfluous tutorial screens. |
| — | Production config audit | ✅ Fixed | Removed dev-fallback secrets in prod; JWT secret, DATABASE_URL, and CORS validated at boot; secrets never logged or returned; upload/rate limits, error handling, Docker, healthchecks reviewed. |
| — | Testing | ✅ Done | Full suite re-run; regression + adversarial tests added (see §5). Coverage increased, not reduced. |
| — | Final E2E verification | ✅ Done | See §6. |

---

## 3. Files Changed

### Backend — logic
- `backend/src/services/scheduler.js` — M1: `computeWeeklyWindow`, per-window dedup, no-data skip,
  `schedule_runs` audit writes, retention sweep timer.
- `backend/src/services/analysis/scope.js` — new `buildScope` window helper.
- `backend/src/services/analysis/{stats,engine,mitre}.js` — window-threaded analysis.
- `backend/src/services/report/builder.js` — window + period-from-window wiring.
- `backend/src/services/report/shareView.js` — executive whitelist redactor; **`redactText`**
  (masks IPv4/IPv6 + cited event-ID fragments), **`redactReportDataForExecutive`** (deep-redacted
  clone for the executive PDF, strips internal `key`/`finding_key` IOCs).
- `backend/src/services/sharing.js` — share `mode` + `share_audit` logging.
- `backend/src/services/retention.js` — M3 engine (`runRetentionForTenant`,
  `runRetentionForAllTenants`, `cutoffFor`).
- `backend/src/config.js` — CORS allow-list parsing + prod env validation + retention config.
- `backend/src/app.js` — CORS origin function + DB-aware `/api/health`.
- `backend/src/db/pool.js` — `pingDb` / `waitForDb`.
- `backend/src/index.js` — `waitForDb` startup gate.
- `backend/src/routes/share.routes.js` — executive default, `buildShareView`, mode-aware PDF
  (executive PDF from redacted clone).
- `backend/src/routes/reports.routes.js` — share-mode passthrough.
- `backend/src/routes/tenant.routes.js` — retention status/run endpoints.
- `backend/src/services/billing/plans.js` — `retentionDays` per plan (enforced by retention.js).

### Frontend
- `backend/public/app.js` — M5 dual-scope KPI cards; share-mode selector (Executive / Analyst with
  confirm warning) + per-share mode badge; onboarding flow + empty states.
- `backend/public/share.html` — mode-aware rendering.

### Deployment / config
- `docker-compose.yml` — named `pgdata` volume, PG `pg_isready` healthcheck, API `depends_on` db
  `service_healthy`, `NODE_ENV=production`, explicit `JWT_SECRET` + `CORS_ORIGIN`,
  `RETENTION_ENABLED`, API healthcheck on `/api/health`, `restart: unless-stopped`.
- `backend/Dockerfile` — `HEALTHCHECK` (wget `/api/health`).
- `.env.example` — CORS prod-hardening doc block + `RETENTION_ENABLED` / `RETENTION_SWEEP_INTERVAL_MS`.

### Tests (added / updated)
- **New:** `config.test.js` (6), `health.test.js` (2), `retention.test.js` (6).
- **Updated:** `scheduling.test.js` (12), `sharing.test.js` (8 — now includes finding-forming
  dataset + PDF-source redaction assertion).

---

## 4. Migration / Schema Changes

Applied as an **idempotent `v2.1` block** in `backend/src/db/schema.sql` (safe to re-run; migration
runs automatically at boot):

- `reports.report_kind` (`manual` | `scheduled`, default `manual`)
- `reports.period_start`, `reports.period_end` (explicit windowing)
- `report_shares.mode` (`executive` default | `analyst`)
- **`schedule_runs`** — audit of scheduled executions (`window_start/end`, `event_count`,
  `status`, `report_id`, `error`)
- **`share_audit`** — share create/access/revoke/expire events
- **`retention_runs`** — auditable retention sweeps (`retention_days`, `*_deleted`, `cutoff`,
  `status`, `run_at`)
- Supporting indexes on the above.

No destructive column drops. Existing rows default to `report_kind='manual'` and share
`mode='executive'`.

---

## 5. Test Results

**`npm test` → 86 tests, 86 pass, 0 fail** (baseline 63).

| Suite | Tests | Focus |
|-------|------:|-------|
| scheduling | 12 | M1: normal window, overlapping windows, duplicate exec, no-data window, timezone boundaries, out-of-order uploads, same-period regeneration |
| sharing | 8 | M2: exec cannot access analyst content (JSON **and** redacted PDF source), analyst only when explicit, cross-tenant blocked, expired/revoked → 410, malicious token rejected, lifecycle audited |
| retention | 6 | M3: cutoff math, deletion of over-age data, preservation of audit/accountability records, tenant-scoping, dry-run, retentionDays≤0 no-op |
| config | 6 | M4: prod refuses empty JWT / wildcard CORS / empty CORS / missing DATABASE_URL; prod accepts explicit allow-list; dev → allowAll |
| health | 2 | `/api/health` reports db up; `waitForDb` fail-safe against dead port |
| upload_robustness | 9 | malformed / large / mixed uploads |
| parser / report / dashboard_v2 / professional_report / comparison_ordering / actions / auth / rbac / tenant / isolation_v1 | 41 | pre-existing coverage, all green |

Adversarial coverage added: scheduler duplication, timezone edges, retention boundaries, share
access-control, cross-tenant isolation, CORS/env misconfig, DB-startup failure, malformed config,
large uploads.

---

## 6. Final End-to-End Verification (live, Postgres-backed)

| Step | Result |
|------|--------|
| Health / DB readiness | `status=ok, db=up` ✅ |
| Tenant signup (E2E Corp, plan=pro) | ✅ |
| Upload 12 events | upload `1ddc99d2…` ✅ |
| Manual report | `3c5a816a…`, `report_kind=manual` ✅ |
| **Executive share — analyst content hidden** | JSON: no `dashboard`, no raw `full_log`, **no source IP**; PDF (3pp): no IP, no raw log, `[redacted-ip]` markers present ✅ |
| **Analyst share — explicit, reveals detail** | `mode=analyst`, hosts/IPs/dashboard present ✅ |
| **Scheduled weekly window** | report `dda79bb5…`, `report_kind=scheduled`, window `2026-09-20 → 2026-09-27`, 8 in-window events (historical upload NOT re-analysed) ✅ |
| **Duplicate prevention** | 2nd + 3rd run → `skipped_duplicate` (auditable in `schedule_runs`) ✅ |
| **Prior-period comparison** | scheduled report compares against prior report with severity deltas ✅ |
| **Retention enforcement** | seeded 400-day-old upload+events → run deleted 1 upload / 3 events (180-day cutoff); recent data + `share_audit` + `schedule_runs` preserved; `retention_runs` row written ✅ |
| **PDF export** | authenticated executive (3pp) + analyst (4pp), valid `%PDF` ✅ |
| **Service restart → persistence** | after stop/start: 2 uploads, 20 events, 3 reports, 3 shares, 1 retention_run all persist; login works; health `ok/db up` ✅ |

---

## 7. Remaining Production Risks & Limitations (explicit)

**Verified in this environment; NOT verified here (must be confirmed by operator):**

1. **Docker / compose not executed.** No Docker daemon is available in the build sandbox, so
   `docker-compose.yml`, the API/DB `HEALTHCHECK`s, `depends_on: service_healthy`, named-volume
   persistence, and `restart` policies were validated by **config review + an equivalent local
   Postgres + Node run**, not by actually running the composed stack. Operator must run
   `docker compose up` once in staging and confirm healthchecks flip to `healthy` and data survives
   `docker compose down && up` (volume persistence).

2. **Backups are operator-owned, not app-enforced.** The app enforces **retention/deletion**, not
   backups. There is no automated `pg_dump`/snapshot or restore tooling shipped. Provision managed
   PITR or a scheduled `pg_dump` externally; the report deliberately does **not** claim enforced
   backups. Recovery limits (RPO/RTO) depend entirely on that external setup.

3. **Retention sweep cadence.** The scheduled sweep interval is env-driven
   (`RETENTION_SWEEP_INTERVAL_MS`, default daily) and also available on-demand. If the process is
   frequently restarted, verify the sweep actually fires in production (the on-demand endpoint is a
   reliable fallback and is what the E2E exercised).

4. **Timezone handling for windows.** Weekly windows are computed in the schedule's configured
   timezone; DST transitions are handled at the boundary but should be spot-checked for any
   non-UTC tenants near a DST switch.

5. **Rate-limiting is in-process.** Share/access rate limits are per-instance; behind multiple
   replicas use a shared store (e.g. Redis) for a global limit.

6. **AI prose is optional and evidence-bound** (deterministic engine is default). If an external AI
   provider is enabled, its output still passes through the same evidence/redaction path, but that
   path should be re-verified against the specific provider before enabling in prod.

**No known open defects** in scheduling correctness, share authorization/redaction, retention
scoping, or tenant isolation as of this verification.

---

## 8. Deployment Instructions

### Prerequisites
- Postgres 14+ (managed or containerised) with a persistent volume and your own backup/PITR.
- Node 18+ (if running outside Docker).

### Required environment (production)
The app **fails fast at boot** if any of these are missing/invalid in `NODE_ENV=production`:

| Var | Notes |
|-----|-------|
| `NODE_ENV=production` | disables dev fallbacks/demo mode |
| `DATABASE_URL` | e.g. `postgres://user:pass@host:5432/soc_copilot` — required |
| `JWT_SECRET` | strong random secret; **prod refuses empty** |
| `CORS_ORIGIN` | explicit comma-separated allow-list (e.g. `https://app.example.com`); **prod refuses wildcard/empty** |
| `RETENTION_ENABLED=true` | enable scheduled retention sweeps |
| `RETENTION_SWEEP_INTERVAL_MS` | optional; default daily |

See `.env.example` for the full annotated list.

### Docker (recommended)
```bash
cp .env.example .env            # set JWT_SECRET, CORS_ORIGIN, DB creds
docker compose up -d --build
# wait for healthy:
docker compose ps               # db + api should report (healthy)
curl -s http://localhost:3000/api/health   # {"status":"ok","db":"up",...}
```
- Postgres data persists in the named `pgdata` volume.
- Both services use `restart: unless-stopped`; API waits for DB `service_healthy` and additionally
  gates on `waitForDb` before serving.

### Bare-metal / Node
```bash
cd backend
npm ci
# schema auto-migrates at boot (idempotent v2.1 block)
NODE_ENV=production node src/index.js
```

### Post-deploy verification checklist
1. `GET /api/health` → `status=ok, db=up`.
2. Confirm CORS: request from an un-listed origin is rejected; listed origin succeeds.
3. Confirm boot **fails** with a clear error if `JWT_SECRET`/`CORS_ORIGIN`/`DATABASE_URL` are
   missing (intentional).
4. Create a schedule, run it, confirm a `schedule_runs` row and a `report_kind=scheduled` report
   with populated `period_start/end`; run again → `skipped_duplicate`.
5. Create an executive share; confirm no IOCs in JSON or PDF. Create an analyst share explicitly;
   confirm detail is present.
6. Trigger retention (`POST /api/tenant/retention/run`); confirm `retention_runs` row and that
   audit records are preserved.
7. Restart the stack; confirm data persists and health returns `ok`.

---

## 9. Production-Readiness Statement

The application meets the audit's acceptance criteria for scheduling correctness, share
authorization/redaction, retention enforcement, CORS/secret hardening, dashboard scoping,
onboarding, and startup/DB reliability, with 86/86 automated tests and a passing live E2E including
restart persistence. **It is not claimed production-ready in the unqualified sense** until the
operator completes the two environment-specific validations in §7: (1) run the Docker stack and
confirm healthchecks + volume persistence in staging, and (2) provision and test database
backups/restore (RPO/RTO), which are intentionally outside the app's enforcement scope.
