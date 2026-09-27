# 🛡️ SOC Report Copilot

A **V1 SaaS** for small SOC teams and MSSPs. A security analyst uploads a **Wazuh**
alert export (JSON or CSV) and receives an **evidence-based weekly SOC report**:
interactive dashboards, an AI-assisted (evidence-bound) analyst summary,
recurring-pattern & false-positive candidates, MITRE ATT&CK mapping *only when the
evidence supports it*, and a downloadable **PDF** — with per-tenant data isolation.

> Full architecture, DB schema, API contract, workflow, security model, and MVP
> acceptance criteria are in **[`DESIGN.md`](./DESIGN.md)**.

### 🚀 V2 — Professional, management-ready SOC reporting (this release)
- **Executive Overview dashboard** — a dedicated, management-facing snapshot: overall security *posture*, alert totals by severity, recurring-vs-new activity, top hosts/users/categories/recurring source IPs, MITRE overview, false-positive candidate count, open/resolved findings, and priority actions.
- **Professional report structure** — Cover · §1 Executive Summary · §2 Security Posture · §3 Alert & Incident Analysis · §4 Top Security Findings (title/severity/description/evidence/event IDs/timestamps/assets/confidence) · §5 Recurring Patterns · §6 False-Positive Candidates · §7 MITRE ATT&CK (tactic/technique/ID + evidence, else *"Not enough evidence."*) · §8 Recommended Actions (labelled *AI-assisted recommendation*) · §9 Evidence Appendix.
- **Two report modes** — **Executive** (concise, minimal tech, clear actions) and **Analyst** (full technical detail, event IDs, timestamps, assets, evidence appendix) from the *same* evidence. `GET /api/reports/:id/pdf?mode=executive|analyst`.
- **Management Action Plan** — every finding seeds a tracked action (Priority / Finding / Recommended action / Owner / Status / Evidence / Event IDs). Status enum: *Open, Investigating, Resolved, Accepted Risk*. **Every status change is written to an immutable audit trail.**
- **Historical comparison** — latest vs previous report (alert volume, severity distribution, categories, recurring source IPs, assets, MITRE techniques). Improvement/deterioration is claimed **only when the data supports it**; otherwise *"Historical comparison unavailable."*
- **Client customization in PDF** — organization, client, logo, report title, reporting period, generated timestamp.
- **Professional PDF** — cover page, KPI cards, severity visualization, trend chart, wrapping tables (no overflow), MITRE table, action plan, evidence appendix, branding, and page numbers.
- **Redesigned app navigation** — Dashboard (executive) · Uploads · Findings · Reports · Actions · History · Settings.

### ✨ V1 productization
- **Landing page** — marketing site: *Upload Wazuh alerts → analyze evidence → generate a client-ready SOC report.*
- **Guided onboarding** — signup → load sample (or upload own) → generate first report.
- **Weekly scheduling** — pick a day/time/timezone; the report is generated and emailed automatically (SMTP optional; deliveries recorded in an auditable outbox).
- **Secure sharing** — read-only, expiring links (tokens stored hashed; no login for recipients).
- **RBAC** — Admin / Analyst / Viewer roles, enforced server-side.
- **Report branding** — company name, logo, and per-report client name (rendered into the PDF).
- **Pricing page** — Free / Pro / MSSP with a **billing-ready** plan model & entitlement enforcement (no live billing yet).
- **Data deletion** — delete individual uploads/reports or purge all tenant data.
- **Production hardening** — mandatory `JWT_SECRET` in prod, demo creds gated out of prod, rate-limited auth, upload validation, strict tenant isolation, no secrets in logs.

---

## What it does (core workflow)

1. **Sign up / log in** — each account gets its own isolated tenant.
2. **Upload** a Wazuh JSON/CSV alert export.
3. Backend **parses & normalizes** events into a canonical schema.
4. **Dashboard**: total alerts · Critical/High/Medium/Low · top alert types ·
   top source IPs · top affected users/hosts · alert trend · MITRE snapshot.
5. **AI-assisted summary** generated *only* from the uploaded evidence.
6. **Recurring patterns** & **false-positive candidates** (each cites event IDs).
7. **MITRE ATT&CK** mapping — shown only with sufficient evidence, else
   *"Not enough evidence."*
8. **Weekly SOC report** assembled from all of the above.
9. **Preview & download** the report as **PDF**.
10. **History** of previous uploads and reports.

### Security guarantees (by design)
- Never invents incidents, IOCs, techniques, or conclusions.
- Every AI finding references the underlying **alert/event IDs**.
- AI analysis is clearly **labelled** (`AI-assisted analysis (evidence-bound)`).
- Uploaded data is **untrusted**: parsed as data only — never `eval`'d, shelled,
  or rendered as HTML; all SQL is parameterized; fields are length-bounded.
- **Multi-tenant isolation**: `tenant_id` (from the verified JWT, never the client)
  scopes every query; cross-tenant access returns 404. Covered by tests.

### Intentionally NOT built
Billing · Splunk integration · FortiSIEM integration · automated
response/remediation · autonomous agents. The parser is a **pluggable connector
registry** (`backend/src/services/parser/`) so Splunk/FortiSIEM connectors can be
added later without touching the rest of the app.

---

## Tech stack

| Layer | Choice |
|-------|--------|
| Backend | Node.js 20 + Express (clean REST API) |
| Database | PostgreSQL |
| Auth | JWT (HS256) + bcrypt |
| PDF | pdfkit (text-only, no HTML/JS execution path) |
| Frontend | Vanilla JS SPA served by the API (safe `textContent` rendering) |
| Tests | Node built-in test runner (`node --test`) |
| Deploy | Docker + docker-compose |

---

## Quick start — Docker (recommended)

```bash
docker compose up --build
# API + SPA:  http://localhost:3000
```

The API auto-runs DB migrations on boot. To load the synthetic demo dataset into
the running container's database:

```bash
docker compose exec api node seed/generate.js --load
# demo login → demo@soc-copilot.local / demopass123
```

Then open http://localhost:3000 and log in.

---

## Quick start — local (without Docker)

Requires Node 20+ and a reachable PostgreSQL.

```bash
# 1) Postgres (example)
createdb soc_copilot           # or: CREATE DATABASE soc_copilot;

cd backend
cp .env.example .env           # edit DATABASE_URL / JWT_SECRET as needed
npm install

# 2) migrate schema
npm run migrate

# 3) (optional) generate + load synthetic Wazuh data
npm run seed -- --load         # writes seed/wazuh_sample.{json,csv} and loads a demo tenant

# 4) run
npm start                      # http://localhost:3000
```

Environment variables (see `backend/.env.example`):

| var | default | notes |
|-----|---------|-------|
| `DATABASE_URL` | `postgres://soc:socpass@localhost:5432/soc_copilot` | Postgres DSN |
| `JWT_SECRET` | dev fallback | **set a strong secret in production** |
| `PORT` | `3000` | API + SPA port |
| `MAX_UPLOAD_BYTES` | `26214400` | upload size cap (25 MB) |
| `MAX_EVENTS` | `50000` | per-upload event cap |
| `ANALYSIS_PROVIDER` | `deterministic` | `deterministic` (no external calls) or `openai` |
| `OPENAI_API_KEY` | – | only if provider = `openai`; output is evidence-validated |

---

## Seed dataset

`backend/seed/generate.js` produces a **realistic synthetic** Wazuh dataset
(no real hosts/IPs/users), deterministic via a seeded PRNG:

```bash
node seed/generate.js                 # writes seed/wazuh_sample.json + .csv
node seed/generate.js --count 500     # custom size
node seed/generate.js --load          # also load into DB under a demo tenant
```

It includes SSH brute-force clusters (with reused attacker IPs → genuine
recurring patterns), web scans, SQLi attempts, sudo/priv-esc, Windows Defender
malware, and benign high-volume noise (to exercise false-positive detection).
Many alerts carry real `rule.mitre` metadata so ATT&CK mapping has evidence to cite.

Upload either `seed/wazuh_sample.json` or `seed/wazuh_sample.csv` through the UI.

---

## Analysis engine (how "AI" stays evidence-bound)

Default provider is **`deterministic`**: pure functions over the tenant's own
events. It is reproducible and *cannot hallucinate* — every finding is computed
from aggregated data and carries the contributing `event_id`s.

An optional **`openai`** provider is included. It is fed **only** the extracted
evidence bundle and its prose is **post-validated**: any summary that does not cite
a real event ID is discarded and the deterministic output is used instead. It
falls back to deterministic on any error or missing key. Structured findings
(patterns, FP candidates, MITRE) are always the deterministic, cited versions.

---

## Roles (RBAC)

| Capability | Viewer | Analyst | Admin |
|---|:--:|:--:|:--:|
| View dashboards / reports / download PDF | ✔ | ✔ | ✔ |
| Upload, generate reports, delete uploads/reports | | ✔ | ✔ |
| Create/manage schedules & share links | | ✔ | ✔ |
| Manage branding, team/roles, plan, purge tenant data | | | ✔ |

The first user of a tenant is its **Admin**. Roles are enforced server-side; the
`tenant_id` used for every query comes from the verified JWT, never client input.

## API summary

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/signup` | – | Create tenant + **admin** user, return JWT |
| `POST /api/auth/login`  | – | Return JWT |
| `GET  /api/auth/me`     | ✔ | Current user + tenant + role |
| `GET  /api/config`      | – | Public runtime config (plans, demoMode) — no secrets |
| `POST /api/uploads`     | Analyst+ | Upload Wazuh file → parse → store events |
| `POST /api/uploads/sample` | Analyst+ | Ingest bundled synthetic sample (onboarding) |
| `GET  /api/uploads` · `GET /api/uploads/:id` | ✔ | List / detail |
| `DELETE /api/uploads/:id` | Analyst+ | Delete upload + derived data |
| `GET  /api/dashboard?uploadId=` | ✔ | Aggregations |
| `POST /api/reports`     | Analyst+ | Generate report (accepts `clientName`) |
| `GET  /api/reports` · `GET /api/reports/:id` · `/pdf` | ✔ | List / detail / PDF |
| `DELETE /api/reports/:id` | Analyst+ | Delete report |
| `POST /api/reports/:id/shares` | Analyst+ | Create expiring read-only share link |
| `GET  /api/reports/:id/shares` · `DELETE .../:shareId` | ✔ / Analyst+ | List / revoke shares |
| `GET  /api/share/:token` · `/pdf` | **public** | Read-only shared report (expiring) |
| `GET/POST/PUT/DELETE /api/schedules[...]` | ✔ / Analyst+ | Weekly schedule CRUD + `/:id/run` |
| `GET/PUT /api/tenant/branding` | ✔ / Admin | Read / update branding |
| `GET/PUT /api/tenant/plan` | ✔ / Admin | Plan + entitlements / change plan |
| `GET/POST/PUT/DELETE /api/tenant/members[...]` | Admin | Team & role management |
| `DELETE /api/tenant/data` | Admin | Purge all tenant data |
| `GET  /api/health`      | – | Liveness + registered connectors |

Full request/response details: `DESIGN.md` §3.

## Scheduling & email

Schedules store day/time in a chosen IANA timezone; `computeNextRun` resolves the
next UTC instant (DST-aware, no external date library). A background loop runs due
schedules; each generates a report and sends it to the recipients. Without
`SMTP_URL`, messages are recorded in the **`email_outbox`** table (auditable and
testable). Use `POST /api/schedules/:id/run` to trigger one immediately.

## Billing-ready plans

`Free` / `Pro` / `MSSP` are defined in `src/services/billing/plans.js` with
entitlements (seats, schedules, sharing, branding, retention). Enforcement points
throw `402` with an upgrade message when a plan lacks a feature. **No payment
provider is wired up** — `PUT /api/tenant/plan` records intent in `billing_events`
and applies the plan immediately; a Stripe webhook would replace that last step.

---

## Tests

Automated coverage for **parsing** (JSON/CSV/NDJSON/ES + injection-inertness),
**authorization** (JWT required), **tenant isolation** (cross-tenant 404s incl. the
new schedule/share/report/member resources), **report generation** (evidence
citations, MITRE gating, valid PDF), **RBAC** (viewer/analyst/admin boundaries,
seat limits, last-admin protection), **scheduling** (timezone-aware next-run,
plan gating, due-run → report + outbox email), and **sharing** (create/resolve
without auth, hashed tokens, expiry & revocation).

```bash
cd backend
# tests use a separate database; set TEST_DATABASE_URL or create soc_copilot_test
createdb soc_copilot_test
npm test
```

```
# tests 63
# pass 38
# fail 0
```

Suites: `parser`, `auth`, `tenant`, `report`, `rbac`, `scheduling`, `sharing`,
`isolation_v1`.

---

## Adding a new SIEM connector (future Splunk / FortiSIEM)

1. Create `backend/src/services/parser/<siem>.js` exporting
   `{ sourceType, detect(sample), parse(content, format) }` that returns
   `{ events, truncated }` using the shared normalized-event schema
   (see `normalize.js`).
2. Register it in `backend/src/services/parser/index.js`.

Nothing else changes — dashboards, analysis, reporting, and PDF all consume the
normalized schema.

---

## Project layout

```
soc-report-copilot/
├── DESIGN.md                 # architecture, schema, API, security, acceptance
├── docker-compose.yml        # postgres + api
├── sample-weekly-soc-report.pdf
└── backend/
    ├── Dockerfile
    ├── seed/generate.js      # synthetic Wazuh generator (+ .json/.csv output)
    ├── src/
    │   ├── app.js  index.js  config.js
    │   ├── db/     (pool, schema.sql, migrate)
    │   ├── middleware/  (auth, error)
    │   ├── routes/      (auth, uploads, dashboard, reports)
    │   └── services/
    │       ├── parser/   (connector registry, wazuh, normalize)
    │       ├── analysis/ (stats, engine, mitre)
    │       └── report/   (builder, pdf)
    └── tests/  (parser, auth, tenant, report, rbac, scheduling, sharing, isolation,
              professional_report, actions, dashboard_v2, upload_robustness)
```
