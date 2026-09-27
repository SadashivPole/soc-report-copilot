# SOC Report Copilot — Design

An MVP SaaS for small SOC teams and MSSPs. A security analyst uploads a Wazuh
alert export (JSON or CSV) and receives an **evidence-based** weekly SOC report:
dashboards, an AI-assisted (evidence-bound) analyst summary, recurring-pattern &
false-positive candidates, MITRE ATT&CK mapping *only when the evidence supports
it*, and a downloadable PDF.

> **Scope guardrails (intentionally NOT built):** billing, Splunk integration,
> FortiSIEM integration, automated response/remediation, autonomous agents.
> The parser layer is a pluggable **connector registry** so Splunk/FortiSIEM
> connectors can be added later without touching the rest of the app.

---

## 1. Architecture

```
                         ┌───────────────────────────────────────────────┐
                         │  Browser SPA (vanilla JS, served by backend)   │
                         │  signup/login · upload · dashboard · report/PDF │
                         └───────────────────────┬───────────────────────┘
                                                 │ HTTPS + JWT (Bearer)
                                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Node.js / Express REST API                                                 │
│                                                                            │
│  middleware:  helmet · cors · rate-limit · JWT auth → {userId, tenantId}   │
│                                                                            │
│  routes ──► services                                                       │
│   /auth        auth.service      (bcrypt, JWT, tenant provisioning)        │
│   /uploads     parser/*          connector registry → wazuh → normalize    │
│   /dashboard   analysis/stats    tenant-scoped aggregations                │
│   /reports     analysis/engine   evidence-bound "AI" analysis engine       │
│                analysis/mitre    ATT&CK mapping (evidence gated)           │
│                report/builder    assemble report object                    │
│                report/pdf        pdfkit → streamed PDF                      │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │ parameterized SQL (pg), tenant_id on every row
                                 ▼
                     ┌───────────────────────────┐
                     │ PostgreSQL                 │
                     │ tenants · users · uploads  │
                     │ events(jsonb) · reports    │
                     └───────────────────────────┘
```

**Design principles**
- **Modular connectors.** `services/parser/index.js` is a registry keyed by
  `source_type`. Today only `wazuh` is registered. A future `splunk.js` /
  `fortisiem.js` only needs to export `{ detect, parse }` and register itself;
  everything downstream consumes the shared *normalized event* schema.
- **Evidence-bound analysis.** The analysis engine is deterministic by default
  and every finding it emits carries the list of `event_id`s that justify it.
  An optional LLM provider can be plugged in (`ANALYSIS_PROVIDER=openai`), but it
  is fed *only* the extracted evidence and is post-validated to drop any claim
  that does not cite real event IDs. Default provider needs no external API.
- **Untrusted input.** Uploaded logs are parsed as data only — never evaluated,
  interpolated into shell/SQL, or rendered as HTML. Output is escaped/drawn as text.

### Normalized event schema (connector output)
```
{ event_id, timestamp, rule_id, rule_description, rule_level, severity,
  groups[], mitre_ids[], mitre_tactics[], mitre_techniques[],
  agent_name, agent_ip, src_ip, dst_ip, src_user, dst_user,
  full_log, decoder, location, raw }
```
Severity is derived from the Wazuh `rule.level` (0–16):
`>=12 Critical · 9–11 High · 6–8 Medium · <=5 Low`.

---

## 2. Database schema

All domain tables carry `tenant_id` and are always queried with a
`WHERE tenant_id = $currentTenant` predicate (see Security model).

| table    | key columns |
|----------|-------------|
| `tenants` | id (uuid pk), name, created_at |
| `users`   | id, tenant_id→tenants, email (unique), password_hash, role, created_at |
| `uploads` | id, tenant_id, user_id, filename, format(json/csv), source_type, event_count, status, error, uploaded_at |
| `events`  | id, tenant_id, upload_id→uploads, event_id, ts, rule_id, rule_description, rule_level, severity, groups(jsonb), mitre(jsonb), agent_name, agent_ip, src_ip, dst_ip, src_user, dst_user, full_log, raw(jsonb), created_at |
| `reports` | id, tenant_id, user_id, upload_id, title, period_start, period_end, data(jsonb), created_at |

Indexes: `(tenant_id)` on every table, plus `events(tenant_id, upload_id)`,
`events(tenant_id, severity)`, `events(tenant_id, ts)`.
Full DDL: `backend/src/db/schema.sql`.

---

## 3. API endpoints

Auth: `Authorization: Bearer <jwt>`. JWT payload = `{ userId, tenantId, role }`.

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/signup` | – | Create tenant + owner user, return JWT |
| `POST /api/auth/login`  | – | Return JWT |
| `GET  /api/auth/me`     | ✔ | Current user + tenant |
| `POST /api/uploads`     | ✔ | multipart file → parse → normalize → store events |
| `GET  /api/uploads`     | ✔ | List this tenant's uploads |
| `GET  /api/uploads/:id` | ✔ | Upload detail (tenant-scoped) |
| `GET  /api/dashboard?uploadId=` | ✔ | Aggregations (totals, severity, top types/IPs/users/hosts, trend) |
| `POST /api/reports`     | ✔ | Generate report for an upload (runs analysis engine) |
| `GET  /api/reports`     | ✔ | List reports |
| `GET  /api/reports/:id` | ✔ | Report JSON (dashboard + findings + MITRE + AI summary) |
| `GET  /api/reports/:id/pdf` | ✔ | Download report as PDF |
| `GET  /api/health`      | – | Liveness |

All list/detail endpoints filter by `tenantId` from the JWT; requesting another
tenant's row returns **404** (not 403) to avoid resource enumeration.

---

## 4. User workflow

1. **Sign up** → a tenant is provisioned and the user becomes its owner; JWT issued.
2. **Log in** → JWT stored in browser (localStorage).
3. **Upload** a Wazuh JSON/CSV export. Backend detects format, runs the Wazuh
   connector, normalizes events, persists them under the tenant + upload.
4. **Dashboard** renders: total alerts; Critical/High/Medium/Low counts; top
   alert types; top source IPs; top affected users/hosts; alert trend over time.
5. **Generate report** → analysis engine produces an evidence-bound summary,
   recurring-pattern findings, false-positive candidates, and MITRE mapping
   (each with cited event IDs, or "Not enough evidence.").
6. **Preview** the report in-app and **download PDF**.
7. **History**: previous uploads and reports are listed and re-openable.

---

## 5. Security model

- **AuthN:** bcrypt password hashing; JWT (HS256) with expiry; secret from env.
- **Multi-tenant isolation:** every domain row has `tenant_id`; the auth
  middleware injects `req.auth.tenantId` from the verified JWT (never from client
  input); every query is parameterized and scoped by that tenant id. Cross-tenant
  access returns 404. Covered by automated tests (`tests/tenant.test.js`).
- **Untrusted uploads:**
  - Parsed strictly as data (JSON.parse / csv-parse). **No `eval`, `Function`,
    template execution, or shell** ever touches log content.
  - File-size cap, event-count cap, and per-field length truncation
    (`full_log` truncated) to bound resource use.
  - All SQL is parameterized (no string concatenation) → no SQL injection.
  - Frontend renders uploaded values via `textContent` / escaping — never
    `innerHTML` — so a malicious log field cannot inject script into the UI.
  - PDF is drawn as text via pdfkit (no HTML/JS execution path).
- **No fabrication:** the analysis engine only emits findings backed by real
  aggregated evidence and attaches the contributing `event_id`s. MITRE mapping is
  gated on evidence (Wazuh `rule.mitre` metadata or a curated deterministic
  rule-group map); with insufficient evidence it emits **"Not enough evidence."**
- **Clear AI labelling:** every generated section is tagged
  `AI-assisted analysis (evidence-bound)` in the API payload, UI, and PDF.
- **Transport/headers:** helmet, CORS allowlist, rate limiting on auth routes.

---

## 6. MVP acceptance criteria

1. A new user can sign up, log in, and receives a scoped JWT.
2. A logged-in user can upload a Wazuh **JSON** export and a Wazuh **CSV**
   export; both normalize into the same event schema.
3. Dashboard returns correct totals, severity breakdown, and top-N lists for the
   uploaded data (verified against the seed dataset).
4. A report can be generated and every AI finding cites underlying event IDs;
   findings with no supporting evidence are omitted; MITRE mapping shows
   "Not enough evidence." when appropriate.
5. Report is downloadable as a valid PDF containing the dashboard summary and the
   clearly-labelled AI analysis.
6. Uploads and reports are listed as history and can be re-opened.
7. **Tenant isolation:** user A cannot read user B's uploads, events, or reports
   (returns 404) — enforced by automated tests.
8. Automated tests pass for: parsing (JSON+CSV), authorization (JWT required),
   tenant isolation, and report generation.
9. `docker compose up` starts Postgres + API; a documented seed command loads
   realistic synthetic Wazuh alerts.

---

## 7. V1 productization addendum

New tables (see `schema.sql`, all tenant-scoped): `report_shares` (hashed tokens,
`expires_at`, `revoked`, view counters), `schedules` (dow/hour/minute/tz,
recipients, `next_run_at`, `last_status`), `email_outbox` (auditable deliveries),
`billing_events` (plan-change intent). `tenants` gains `company_name`,
`logo_data_url`, `default_client`, `plan`, `plan_status`, `billing_customer_ref`;
`reports` gains `client_name`. Legacy `owner` role is normalized to `admin`.

**RBAC** — roles `viewer < analyst < admin` (`middleware/auth.js: requireRole`).
Enforced on uploads/reports/schedules/shares (analyst+) and branding/team/plan/
purge (admin). Last-admin demotion is blocked.

**Scheduling** — `services/scheduler.js` computes the next UTC run for a
weekly dow/time in an IANA timezone (DST-aware, no external lib) and a background
loop (`startScheduler`) executes due schedules: build report → persist →
email via `services/mailer.js`. `runDueSchedules(now)` and `computeNextRun(...)`
are pure/exported for tests.

**Sharing** — `services/sharing.js` mints a random token, stores only its
sha256 hash, and resolves public read-only access with expiry/revocation checks.
Public routes (`/api/share/:token[/pdf]`, `/share/:token`) require no auth and
never expose tenant identifiers.

**Billing-ready** — `services/billing/plans.js` defines Free/Pro/MSSP with
entitlement limits; `assertEntitled()` throws `402` where a plan lacks a feature.
No payment provider is integrated; `PUT /api/tenant/plan` logs intent and applies
the plan directly (the point a Stripe webhook would later own).

**Security hardening** — production requires a strong `JWT_SECRET` (startup
refuses otherwise); demo credentials/hints are gated behind `demoMode` (off in
prod) and the seeder refuses to run in prod without `--force`; auth endpoints and
public share resolution are rate-limited; uploads are extension/size/emptiness
validated and parsed as inert data; errors/handlers log messages only (no secrets),
and `/api/config` exposes only non-sensitive fields.

### Acceptance criteria (V1, in addition to §6)
10. Public landing explains Upload → Analyze → Report and routes to signup/pricing.
11. Onboarding guides signup → upload/sample → first report.
12. A weekly schedule generates & "sends" a report at the chosen local time; a
    delivery record appears in the outbox; `next_run_at` advances.
13. A share link grants read-only access that expires and can be revoked; tokens
    are never stored in plaintext.
14. RBAC prevents viewers from writing and non-admins from managing the tenant.
15. Branding (company/logo/client) appears in the generated PDF.
16. Plans gate scheduling/sharing/branding/seats and surface an upgrade path.
17. Automated tests cover scheduling, RBAC, sharing, and tenant isolation.

## 8. V2 professional reporting addendum

Builds on V1; **inspect-and-extend** (no rebuild). No new SIEM connectors, no
live billing, no autonomous response.

### New/changed data model
- `reports.organization`, `reports.previous_report_id`.
- `actions` — management action plan (tenant-scoped): `priority` (P1–P4),
  `finding`, `recommended_action`, `owner`, `status`
  (`open|investigating|resolved|accepted_risk`), `evidence` (JSONB:
  `{event_ids, source, first_seen, last_seen, assets}`), `finding_key` (dedup),
  `ai_assisted`.
- `action_history` — immutable audit row per status change
  (`from_status`, `to_status`, `note`, `changed_by`, `changed_at`).

### Report `data` object (superset — legacy keys preserved)
`meta{title,organization,client_name,period_*,generated_at,posture}`, `kpis`,
`executive_summary`, `security_posture`, `analysis_section`, `findings[]`
(each cites `evidence.event_ids` + timestamps + assets + confidence),
`recurring_patterns[]`, `false_positive_candidates[]`, `mitre_section`
(tactic/technique/ID + evidence, else `note`), `recommended_actions[]`
(labelled *AI-assisted recommendation*), `evidence_appendix[]`, `comparison`.
Legacy keys `dashboard`, `ai_analysis`, `mitre_attack`, `title`, `client_name`,
`branding` remain for backward compatibility.

### New endpoints
- `GET /api/dashboard/executive[?uploadId=]` — executive overview payload.
- `GET /api/reports/:id/pdf?mode=executive|analyst` — two rendering modes.
- `GET /api/actions[?status=]`, `GET /api/actions/summary`,
  `GET /api/actions/:id` (with history), `POST /api/actions` (Analyst+),
  `PATCH /api/actions/:id` (Analyst+, audit-logged), `DELETE /api/actions/:id`
  (Admin). Report generation auto-seeds actions from recommended actions
  (dedup by `finding_key` across active actions).

### AI safety (unchanged principle, extended surface)
Deterministic engine remains the default. Findings, recommended actions, posture
and comparison are pure functions over the tenant's own evidence. No finding is
emitted without citing real event IDs; MITRE stays evidence-gated; comparison
only claims a trend the two data snapshots support.

### Acceptance criteria (V2, in addition to §6/§7)
18. Executive Overview renders posture, severity totals, recurring/new activity,
    top hosts/users/categories/recurring IPs, MITRE overview, FP count and
    open/resolved findings.
19. Report contains all nine sections; every finding cites event IDs.
20. Executive and Analyst PDFs both render (valid `%PDF`, no table overflow,
    page numbers, branding, generated timestamp).
21. Action status changes are persisted with an audit history.
22. Historical comparison is unavailable-safe and only claims data-supported
    trends.
23. Tenant isolation and authn/authz hold on all new endpoints.
24. Full test suite passes (63 tests, incl. audit regression tests for chronological comparison ordering and alert-frequency labelling).
