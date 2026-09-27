'use strict';
/**
 * Connector registry. This is the extension point for future SIEM sources.
 * To add Splunk/FortiSIEM later: implement a module exporting
 * { sourceType, detect(sample), parse(content, format) } and register it here.
 * Everything downstream consumes the shared normalized-event schema, so no other
 * part of the app changes.
 */
const wazuh = require('./wazuh');

const connectors = new Map();
function register(connector) {
  connectors.set(connector.sourceType, connector);
}
register(wazuh);
// register(require('./splunk'));      // future
// register(require('./fortisiem'));   // future

function getConnector(sourceType) {
  const c = connectors.get(sourceType);
  if (!c) throw new Error(`Unknown source type: ${sourceType}`);
  return c;
}

function listSources() {
  return [...connectors.keys()];
}

module.exports = { getConnector, listSources, register };
