'use strict';
const config = require('../config');
const { query } = require('../db/pool');

/**
 * Mail abstraction. Every message is first recorded in `email_outbox` (auditable,
 * testable, never lost). If an SMTP URL is configured we additionally attempt
 * real delivery via nodemailer *if it is installed*; otherwise the outbox row is
 * the delivery record (suitable for dev and CI). Secrets are never logged.
 */
async function sendReportEmail({ tenantId, to, subject, body, reportId }) {
  const recipients = (Array.isArray(to) ? to : [to]).filter(Boolean);
  const ins = await query(
    `INSERT INTO email_outbox(tenant_id, to_addrs, subject, body, report_id, status)
     VALUES($1,$2,$3,$4,$5,'queued') RETURNING id`,
    [tenantId, JSON.stringify(recipients), subject, body, reportId || null]
  );
  const outboxId = ins.rows[0].id;

  if (!config.mail.smtpUrl || recipients.length === 0) {
    // No transport configured (or nobody to send to): the outbox row IS the record.
    await query(`UPDATE email_outbox SET status='sent', sent_at=now() WHERE id=$1`, [outboxId]);
    return { outboxId, delivered: false, recorded: true };
  }

  try {
    // Lazy, optional dependency — not required for the app to run.
    // eslint-disable-next-line global-require, import/no-unresolved
    const nodemailer = require('nodemailer');
    const transport = nodemailer.createTransport(config.mail.smtpUrl);
    await transport.sendMail({ from: config.mail.from, to: recipients.join(','), subject, text: body });
    await query(`UPDATE email_outbox SET status='sent', sent_at=now() WHERE id=$1`, [outboxId]);
    return { outboxId, delivered: true, recorded: true };
  } catch (e) {
    // Redact: store only a short, non-sensitive error string.
    const safe = String(e.message || 'send failed').slice(0, 200);
    await query(`UPDATE email_outbox SET status='failed', error=$2 WHERE id=$1`, [outboxId, safe]);
    return { outboxId, delivered: false, recorded: true, error: safe };
  }
}

module.exports = { sendReportEmail };
