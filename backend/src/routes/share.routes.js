'use strict';
// PUBLIC, unauthenticated, READ-ONLY access to a shared report via an opaque
// expiring token. No tenant context is exposed; only the report payload is served.
const express = require('express');
const rateLimit = require('express-rate-limit');
const sharing = require('../services/sharing');
const { renderReportPdf } = require('../services/report/pdf');
const { buildShareView, redactReportDataForExecutive } = require('../services/report/shareView');

const router = express.Router();

// Rate-limit public share resolution to blunt token guessing.
const shareLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
router.use(shareLimiter);

function statusFor(result) {
  if (!result) return { code: 404, error: 'Link not found' };
  if (result.error === 'expired') return { code: 410, error: 'This share link has expired' };
  if (result.error === 'revoked') return { code: 410, error: 'This share link has been revoked' };
  return null;
}

router.get('/:token', async (req, res, next) => {
  try {
    const result = await sharing.resolveShare(req.params.token);
    const bad = statusFor(result);
    if (bad) return res.status(bad.code).json({ error: bad.error });
    // Serve only the disclosure level the share was created for. Executive shares
    // never expose raw logs / hostnames / usernames / event IDs.
    const viewData = buildShareView(result.report.data, result.mode);
    res.json({
      shared: true,
      mode: result.mode,
      expires_at: result.expires_at,
      report: { ...result.report, data: viewData },
    });
  } catch (e) { next(e); }
});

router.get('/:token/pdf', async (req, res, next) => {
  try {
    const result = await sharing.resolveShare(req.params.token);
    const bad = statusFor(result);
    if (bad) return res.status(bad.code).json({ error: bad.error });
    // PDF disclosure matches the share mode. The executive PDF is rendered from a
    // deep-redacted copy so no raw logs / hostnames / users / IPs / event IDs leak.
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="soc-report-${result.mode}.pdf"`);
    const pdfData = result.mode === 'analyst' ? result.report.data : redactReportDataForExecutive(result.report.data);
    renderReportPdf(pdfData, res, { mode: result.mode });
  } catch (e) { next(e); }
});

module.exports = router;
