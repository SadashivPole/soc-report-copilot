'use strict';
const { parse: parseCsvSync } = require('csv-parse/sync');
const { buildNormalized } = require('./normalize');
const config = require('../../config');

/** Safe nested getter: get(obj, 'rule.level'). Never throws on bad input. */
function get(obj, path) {
  if (!obj || typeof obj !== 'object') return undefined;
  let cur = obj;
  for (const key of path.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[key];
  }
  return cur;
}

/** First defined value among candidate paths. */
function pick(obj, paths) {
  for (const p of paths) {
    const v = get(obj, p);
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

/** Extract normalized-ready fields from one raw Wazuh alert object. */
function extractFields(a) {
  return {
    event_id: pick(a, ['id', '_id', 'alert_id', 'rule.firedtimes_id']),
    timestamp: pick(a, ['timestamp', '@timestamp', 'time', 'data.timestamp']),
    rule_id: pick(a, ['rule.id', 'rule_id']),
    rule_description: pick(a, ['rule.description', 'rule_description', 'description']),
    rule_level: pick(a, ['rule.level', 'rule_level', 'level']),
    groups: pick(a, ['rule.groups', 'rule_groups', 'groups']),
    mitre_ids: pick(a, ['rule.mitre.id', 'rule.mitre.ids', 'mitre.id']),
    mitre_tactics: pick(a, ['rule.mitre.tactic', 'rule.mitre.tactics', 'mitre.tactic']),
    mitre_techniques: pick(a, ['rule.mitre.technique', 'rule.mitre.techniques', 'mitre.technique']),
    agent_name: pick(a, ['agent.name', 'agent_name', 'manager.name']),
    agent_ip: pick(a, ['agent.ip', 'agent_ip']),
    src_ip: pick(a, ['data.srcip', 'data.src_ip', 'srcip', 'data.win.eventdata.ipAddress']),
    dst_ip: pick(a, ['data.dstip', 'data.dst_ip', 'dstip']),
    src_user: pick(a, ['data.srcuser', 'data.src_user', 'srcuser', 'data.win.eventdata.targetUserName']),
    dst_user: pick(a, ['data.dstuser', 'data.dst_user', 'dstuser']),
    full_log: pick(a, ['full_log', 'message', 'data.full_log']),
    decoder: pick(a, ['decoder.name', 'decoder', 'predecoder.program_name']),
    location: pick(a, ['location', 'log.file.path']),
  };
}

/** Retain a bounded copy of the raw object for evidence/audit (no huge blobs). */
function boundRaw(a) {
  try {
    const s = JSON.stringify(a);
    if (s.length <= 8000) return a;
    return { _truncated: true, _preview: s.slice(0, 8000) };
  } catch {
    return { _unserializable: true };
  }
}

/** Parse a Wazuh JSON payload: array, NDJSON, {alerts:[]}, or ES {hits:{hits:[]}}. */
function parseJson(text) {
  let root;
  const trimmed = text.trim();
  try {
    root = JSON.parse(trimmed);
  } catch {
    // Try NDJSON (one JSON object per line)
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
    const arr = [];
    for (const line of lines) {
      try {
        arr.push(JSON.parse(line));
      } catch {
        /* skip malformed line — untrusted input, do not throw the whole batch */
      }
    }
    if (!arr.length) throw new Error('Input is not valid JSON or NDJSON');
    root = arr;
  }

  let alerts;
  if (Array.isArray(root)) alerts = root;
  else if (Array.isArray(root.alerts)) alerts = root.alerts;
  else if (Array.isArray(root.events)) alerts = root.events;
  else if (get(root, 'hits.hits')) alerts = get(root, 'hits.hits').map((h) => h._source || h);
  else if (root.rule || root.agent) alerts = [root];
  else throw new Error('Could not locate an array of Wazuh alerts in JSON');

  return alerts;
}

/** Parse a Wazuh CSV export with dotted or flat column headers. */
function parseCsv(text) {
  const records = parseCsvSync(text, {
    columns: true,
    skip_empty_lines: true,
    relax_column_count: true,
    trim: true,
    bom: true,
  });
  // Reconstruct a shallow "object with dotted keys" that get() can read.
  return records.map((row) => {
    const obj = {};
    for (const [k, v] of Object.entries(row)) obj[k] = v;
    // Provide dotted-path lookups by also nesting.
    for (const [k, v] of Object.entries(row)) {
      if (k.includes('.')) {
        const parts = k.split('.');
        let cur = obj;
        for (let i = 0; i < parts.length - 1; i++) {
          cur[parts[i]] = cur[parts[i]] && typeof cur[parts[i]] === 'object' ? cur[parts[i]] : {};
          cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = v;
      }
    }
    return obj;
  });
}

const wazuh = {
  sourceType: 'wazuh',

  /** Lightweight heuristic used by the registry to auto-detect Wazuh data. */
  detect(sample) {
    if (!sample) return false;
    const s = typeof sample === 'string' ? sample.toLowerCase() : '';
    return (
      s.includes('rule.level') ||
      s.includes('"rule"') ||
      s.includes('"agent"') ||
      s.includes('rule.description')
    );
  },

  /**
   * @param {Buffer|string} content
   * @param {'json'|'csv'} format
   * @returns {{events: object[], truncated: boolean}}
   */
  parse(content, format) {
    const text = Buffer.isBuffer(content) ? content.toString('utf8') : String(content);
    const rawAlerts = format === 'csv' ? parseCsv(text) : parseJson(text);

    if (!Array.isArray(rawAlerts) || rawAlerts.length === 0) {
      throw new Error('No alerts found in upload');
    }

    let truncated = false;
    let list = rawAlerts;
    if (list.length > config.limits.maxEvents) {
      list = list.slice(0, config.limits.maxEvents);
      truncated = true;
    }

    const events = list.map((a, i) => buildNormalized(extractFields(a), boundRaw(a), i));
    return { events, truncated };
  },
};

module.exports = wazuh;
