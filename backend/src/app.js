'use strict';
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');
const { errorHandler, notFound } = require('./middleware/error');
const { listSources } = require('./services/parser');
const { listPlans } = require('./services/billing/plans');
const { pingDb } = require('./db/pool');

const authRoutes = require('./routes/auth.routes');
const uploadRoutes = require('./routes/uploads.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const reportRoutes = require('./routes/reports.routes');
const tenantRoutes = require('./routes/tenant.routes');
const scheduleRoutes = require('./routes/schedules.routes');
const shareRoutes = require('./routes/share.routes');
const actionRoutes = require('./routes/actions.routes');

function createApp() {
  const app = express();

  // Behind the preview/proxy: trust the first proxy so rate-limit & req.protocol work.
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // helmet with a CSP compatible with our self-hosted inline SPA.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          frameAncestors: ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );
  // CORS: permissive in development; strict allow-list in production.
  const corsOptions = config.cors.allowAll
    ? { origin: true }
    : {
        origin(origin, cb) {
          // Requests with no Origin header (same-origin, curl, server-to-server) are allowed.
          if (!origin) return cb(null, true);
          if (config.cors.origins.includes(origin)) return cb(null, true);
          return cb(new Error('Origin not allowed by CORS'), false);
        },
      };
  app.use(cors(corsOptions));
  // Larger JSON limit only to accommodate base64 logo uploads on branding.
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  // Liveness + readiness. Verifies the database is actually reachable so an
  // orchestrator can restart / stop routing traffic when Postgres is down.
  app.get('/api/health', async (req, res) => {
    const db = await pingDb();
    const body = { status: db.ok ? 'ok' : 'degraded', db: db.ok ? 'up' : 'down', sources: listSources(), time: new Date().toISOString() };
    res.status(db.ok ? 200 : 503).json(body);
  });

  // Public, non-sensitive runtime config for the SPA (no secrets).
  app.get('/api/config', (req, res) =>
    res.json({
      appName: 'SOC Report Copilot',
      demoMode: config.demoMode,
      defaultPlan: config.defaultPlan,
      analysisProvider: config.analysis.provider,
      plans: listPlans(),
    })
  );

  app.use('/api/auth', authRoutes);
  app.use('/api/uploads', uploadRoutes);
  app.use('/api/dashboard', dashboardRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/tenant', tenantRoutes);
  app.use('/api/schedules', scheduleRoutes);
  app.use('/api/actions', actionRoutes);
  app.use('/api/share', shareRoutes); // public, read-only

  // Static SPA
  const publicDir = path.join(__dirname, '..', 'public');
  app.use(express.static(publicDir));
  // Public read-only share viewer.
  app.get('/share/:token', (req, res) => res.sendFile(path.join(publicDir, 'share.html')));
  app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

  app.use('/api', notFound);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
