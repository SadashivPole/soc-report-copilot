'use strict';
/**
 * Generate a realistic synthetic Wazuh alert dataset (JSON + CSV).
 * No real hosts/IPs/users. Deterministic via a seeded PRNG so tests are stable.
 *
 * Usage:
 *   node seed/generate.js            # writes seed/wazuh_sample.{json,csv}
 *   node seed/generate.js --count 400
 *   node seed/generate.js --load     # also load into DB under a demo tenant
 */
const fs = require('fs');
const path = require('path');

// --- tiny seeded PRNG (mulberry32) so output is reproducible ---
function mulberry32(seed) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(1337);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const int = (a, b) => a + Math.floor(rand() * (b - a + 1));

const HOSTS = ['web01', 'web02', 'db01', 'app01', 'app02', 'mail01', 'bastion01', 'k8s-node1'];
const INTERNAL = () => `10.0.${int(0, 4)}.${int(2, 250)}`;
const EXTERNAL = () => `${int(11, 223)}.${int(0, 255)}.${int(0, 255)}.${int(1, 254)}`;
const USERS = ['root', 'admin', 'jdoe', 'asmith', 'svc_backup', 'postgres', 'www-data', 'ubuntu'];

// Alert archetypes. `mitre` present ONLY where a Wazuh rule would legitimately
// carry ATT&CK metadata — so evidence-gated mapping has something real to cite.
const ARCHETYPES = [
  {
    weight: 26,
    rule: { id: '5710', level: 5, description: 'sshd: Attempt to login using a non-existent user', groups: ['syslog', 'sshd', 'authentication_failed', 'invalid_login'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
    decoder: 'sshd', location: '/var/log/auth.log',
    make: () => ({ srcip: EXTERNAL(), dstuser: pick(USERS) }),
    log: (d) => `Failed password for invalid user ${d.dstuser} from ${d.srcip} port ${int(1024, 65535)} ssh2`,
  },
  {
    weight: 18,
    rule: { id: '5712', level: 10, description: 'sshd: Multiple authentication failures (possible brute force)', groups: ['syslog', 'sshd', 'authentication_failures', 'brute_force'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
    decoder: 'sshd', location: '/var/log/auth.log',
    make: () => ({ srcip: EXTERNAL(), dstuser: pick(USERS) }),
    log: (d) => `Multiple SSH authentication failures from ${d.srcip} (user ${d.dstuser})`,
  },
  {
    weight: 12,
    rule: { id: '31151', level: 6, description: 'Multiple web server 400 error codes from same source ip', groups: ['web', 'accesslog', 'web_scan', 'recon'], mitre: { id: ['T1595'], tactic: ['Reconnaissance'], technique: ['Active Scanning'] } },
    decoder: 'web-accesslog', location: '/var/log/nginx/access.log',
    make: () => ({ srcip: EXTERNAL() }),
    log: (d) => `${d.srcip} - - "GET /wp-admin/setup-config.php HTTP/1.1" 404`,
  },
  {
    weight: 8,
    rule: { id: '5402', level: 3, description: 'Successful sudo to ROOT executed', groups: ['syslog', 'sudo', 'privilege_escalation'], mitre: { id: ['T1548.003'], tactic: ['Privilege Escalation'], technique: ['Sudo and Sudo Caching'] } },
    decoder: 'sudo', location: '/var/log/auth.log',
    make: () => ({ srcuser: pick(USERS), dstuser: 'root' }),
    log: (d) => `${d.srcuser} : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/apt update`,
  },
  {
    weight: 10,
    rule: { id: '5501', level: 3, description: 'PAM: Login session opened', groups: ['pam', 'syslog', 'authentication_success'] },
    decoder: 'pam', location: '/var/log/auth.log',
    make: () => ({ srcuser: pick(USERS) }),
    log: (d) => `pam_unix(sshd:session): session opened for user ${d.srcuser}`,
  },
  {
    weight: 9,
    rule: { id: '550', level: 7, description: 'Integrity checksum changed', groups: ['ossec', 'syscheck'] },
    decoder: 'syscheck', location: 'syscheck',
    make: () => ({}),
    log: () => `File '/etc/passwd' checksum changed.`,
  },
  {
    weight: 6,
    rule: { id: '87105', level: 12, description: 'Windows: Malware detected by Windows Defender', groups: ['windows', 'malware', 'defender'], mitre: { id: ['T1059'], tactic: ['Execution'], technique: ['Command and Scripting Interpreter'] } },
    decoder: 'windows_eventchannel', location: 'EventChannel',
    make: () => ({ dstuser: pick(USERS) }),
    log: (d) => `Windows Defender detected Trojan:Win32/Wacatac on account ${d.dstuser}`,
  },
  {
    weight: 5,
    rule: { id: '100201', level: 13, description: 'Possible exploitation of public-facing application (SQLi pattern)', groups: ['web', 'attack', 'sql_injection'], mitre: { id: ['T1190'], tactic: ['Initial Access'], technique: ['Exploit Public-Facing Application'] } },
    decoder: 'web-accesslog', location: '/var/log/nginx/access.log',
    make: () => ({ srcip: EXTERNAL() }),
    log: (d) => `${d.srcip} - - "GET /products?id=1' OR '1'='1 HTTP/1.1" 200`,
  },
  {
    weight: 6,
    rule: { id: '533', level: 3, description: 'Netstat listened ports status changed', groups: ['ossec', 'monitor'] },
    decoder: 'ossec', location: 'netstat',
    make: () => ({}),
    log: () => `Listened ports status changed (netstat).`,
  },
];

function weightedArchetype() {
  const total = ARCHETYPES.reduce((s, a) => s + a.weight, 0);
  let r = rand() * total;
  for (const a of ARCHETYPES) {
    if ((r -= a.weight) <= 0) return a;
  }
  return ARCHETYPES[0];
}

function generate(count) {
  const alerts = [];
  const now = Date.now();
  const weekMs = 7 * 24 * 3600 * 1000;

  // A few persistent "attacker" IPs to create genuine recurring patterns.
  const attackerIps = [EXTERNAL(), EXTERNAL(), EXTERNAL()];

  for (let i = 0; i < count; i++) {
    const a = weightedArchetype();
    const d = a.make();
    // Bias brute-force archetypes to reuse attacker IPs → recurring evidence.
    if (a.rule.groups.includes('brute_force') || a.rule.groups.includes('authentication_failed')) {
      if (rand() < 0.7) d.srcip = pick(attackerIps);
    }
    const ts = new Date(now - Math.floor(rand() * weekMs)).toISOString();
    const host = pick(HOSTS);
    const alert = {
      id: `169${String(1000000 + i)}.${int(100000, 999999)}`,
      timestamp: ts,
      rule: {
        id: a.rule.id,
        level: a.rule.level,
        description: a.rule.description,
        groups: a.rule.groups,
        firedtimes: int(1, 40),
        ...(a.rule.mitre ? { mitre: a.rule.mitre } : {}),
      },
      agent: { id: String(int(1, 20)).padStart(3, '0'), name: host, ip: INTERNAL() },
      manager: { name: 'wazuh-manager' },
      decoder: { name: a.decoder },
      location: a.location,
      data: {
        ...(d.srcip ? { srcip: d.srcip } : {}),
        ...(d.srcuser ? { srcuser: d.srcuser } : {}),
        ...(d.dstuser ? { dstuser: d.dstuser } : {}),
      },
      full_log: a.log(d),
    };
    alerts.push(alert);
  }
  // sort chronologically
  alerts.sort((x, y) => new Date(x.timestamp) - new Date(y.timestamp));
  return alerts;
}

function toCsv(alerts) {
  const cols = [
    'id', 'timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.groups',
    'rule.mitre.id', 'agent.name', 'agent.ip', 'data.srcip', 'data.srcuser',
    'data.dstuser', 'decoder.name', 'location', 'full_log',
  ];
  const esc = (v) => {
    const s = v === undefined || v === null ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const get = (o, p) => p.split('.').reduce((c, k) => (c ? c[k] : undefined), o);
  const rows = alerts.map((a) =>
    cols
      .map((c) => {
        let v = get(a, c);
        if (Array.isArray(v)) v = v.join(',');
        return esc(v);
      })
      .join(',')
  );
  return [cols.join(','), ...rows].join('\n');
}

async function loadIntoDb(alerts) {
  // Production hardening: refuse to seed demo credentials into a prod database
  // unless explicitly forced.
  if (process.env.NODE_ENV === 'production' && !process.argv.includes('--force')) {
    console.error('[seed] Refusing to load demo data/credentials in production. Pass --force to override.');
    process.exit(1);
  }
  const bcrypt = require('bcryptjs');
  const { query, withTransaction, pool } = require('../src/db/pool');
  const { migrate } = require('../src/db/migrate');
  const { getConnector } = require('../src/services/parser');
  await migrate();

  const email = 'demo@soc-copilot.local';
  const password = 'demopass123';
  await query('DELETE FROM users WHERE email=$1', [email]).catch(() => {});
  const hash = await bcrypt.hash(password, 10);
  const { tenantId, uploadId } = await withTransaction(async (client) => {
    const t = await client.query(
      "INSERT INTO tenants(name, company_name, default_client, plan) VALUES('Demo SOC Team','Demo SOC Team','Acme Corp','pro') RETURNING id"
    );
    const tenantId = t.rows[0].id;
    const u = await client.query(
      "INSERT INTO users(tenant_id,email,password_hash,role) VALUES($1,$2,$3,'admin') RETURNING id",
      [tenantId, email, hash]
    );
    const userId = u.rows[0].id;
    const up = await client.query(
      "INSERT INTO uploads(tenant_id,user_id,filename,format,source_type,event_count,status) VALUES($1,$2,'wazuh_sample.json','json','wazuh',$3,'parsed') RETURNING id",
      [tenantId, userId, alerts.length]
    );
    return { tenantId, uploadId: up.rows[0].id };
  });

  const { events } = getConnector('wazuh').parse(JSON.stringify(alerts), 'json');
  for (const ev of events) {
    await query(
      `INSERT INTO events(tenant_id,upload_id,event_id,ts,rule_id,rule_description,rule_level,severity,groups,mitre,agent_name,agent_ip,src_ip,dst_ip,src_user,dst_user,full_log,raw)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
      [
        tenantId, uploadId, ev.event_id, ev.timestamp, ev.rule_id, ev.rule_description,
        ev.rule_level, ev.severity, JSON.stringify(ev.groups),
        JSON.stringify({ ids: ev.mitre_ids, tactics: ev.mitre_tactics, techniques: ev.mitre_techniques }),
        ev.agent_name, ev.agent_ip, ev.src_ip, ev.dst_ip, ev.src_user, ev.dst_user, ev.full_log, JSON.stringify(ev.raw),
      ]
    );
  }
  console.log(`[seed] loaded ${events.length} events for demo tenant`);
  console.log(`[seed] demo login → email: ${email}  password: ${password}`);
  await pool.end();
}

async function main() {
  const args = process.argv.slice(2);
  const countArg = args.indexOf('--count');
  const count = countArg >= 0 ? parseInt(args[countArg + 1], 10) : 350;
  const alerts = generate(count);

  const outDir = __dirname;
  fs.writeFileSync(path.join(outDir, 'wazuh_sample.json'), JSON.stringify(alerts, null, 2));
  fs.writeFileSync(path.join(outDir, 'wazuh_sample.csv'), toCsv(alerts));
  console.log(`[seed] wrote ${alerts.length} alerts → wazuh_sample.json / wazuh_sample.csv`);

  if (args.includes('--load')) await loadIntoDb(alerts);
}

if (require.main === module) {
  main().catch((e) => {
    console.error('[seed] failed:', e.message);
    process.exit(1);
  });
}

module.exports = { generate, toCsv };
