'use strict';
const config = require('./config');
const { createApp } = require('./app');
const { migrate } = require('./db/migrate');
const { pool, waitForDb } = require('./db/pool');
const { startScheduler } = require('./services/scheduler');

async function main() {
  // Fail safely if the database is unavailable: wait/retry with a clear message
  // rather than crash-looping. If it never comes up, exit non-zero so the
  // orchestrator's restart policy takes over.
  const ready = await waitForDb();
  if (!ready) {
    console.error('[server] database unreachable after retries — refusing to start.');
    process.exit(1);
  }
  // Auto-migrate on boot so `docker compose up` is single-command.
  await migrate();
  const app = createApp();
  const server = app.listen(config.port, '0.0.0.0', () => {
    console.log(`[server] SOC Report Copilot API listening on 0.0.0.0:${config.port}`);
    console.log(`[server] env=${config.env} · analysis provider: ${config.analysis.provider} · demoMode=${config.demoMode}`);
  });

  // Background weekly-report scheduler (no-op if disabled).
  startScheduler();

  const shutdown = async (sig) => {
    console.log(`[server] ${sig} received, shutting down`);
    server.close(() => {});
    await pool.end().catch(() => {});
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Never dump full error objects (which may contain connection strings/tokens);
// log only the message.
process.on('unhandledRejection', (err) => console.error('[server] unhandledRejection:', (err && err.message) || err));
process.on('uncaughtException', (err) => console.error('[server] uncaughtException:', (err && err.message) || err));

main().catch((err) => {
  console.error('[server] fatal:', err.message);
  process.exit(1);
});
