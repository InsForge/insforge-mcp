#!/usr/bin/env node
/**
 * Post-deploy acceptance check for a running insforge-mcp.
 *
 *   node scripts/verify-deploy.mjs https://mcp.insforge.dev [expected-version]
 *
 * Read-only: it fetches discovery documents and makes one unauthenticated MCP
 * request. It registers nothing and writes nothing. Exits non-zero on the first
 * failed assertion so it can gate a deploy.
 *
 * This encodes the checks that were run by hand while diagnosing the stale
 * deployment, so "did the deploy actually fix it" is a command rather than a
 * thread someone has to find.
 */

const base = (process.argv[2] || '').replace(/\/$/, '');
const expectedVersion = process.argv[3];

if (!base) {
  console.error('usage: verify-deploy.mjs <base-url> [expected-version]');
  process.exit(2);
}

const results = [];
let failed = 0;

const baseOrigin = new URL(base).origin;

/**
 * Record an assertion.
 *
 * scope 'target'   — describes the deployment named on the command line.
 * scope 'external' — describes some other host the documents pointed us at.
 *   These are reported but never scored. Before a DNS cutover the box under
 *   test still advertises the FINAL hostname as its authorization server, so
 *   following that chain scores the machine being replaced. Counting those as
 *   passes makes a fifth of the gate green because the old box is still up.
 */
function check(name, ok, detail, scope = 'target') {
  results.push({ name, ok, detail, scope });
  if (!ok && scope === 'target') failed++;
}

async function getJson(path) {
  const res = await fetch(base + path, { headers: { accept: 'application/json' } });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: res.status, body, headers: res.headers };
}

// --- health, and the deployed version -------------------------------------
const health = await getJson('/health');
check('GET /health is 200', health.status === 200, `status ${health.status}`);
if (expectedVersion) {
  check(
    `/health reports version ${expectedVersion}`,
    health.body?.version === expectedVersion,
    `got ${health.body?.version}`
  );
}

// Runtime sessions should not run away from the ones Redis still holds. A
// small excess is normal in-flight; an order of magnitude is the leak.
const sessions = health.body?.sessions;
if (sessions) {
  const { activeSessions: active = 0, memorySessionCount: resident = 0 } = sessions;
  check(
    'resident sessions are not far above active ones',
    resident <= Math.max(active * 2, active + 50),
    `active=${active} resident=${resident}`
  );
}

// --- the 401 has to tell a client where to look ---------------------------
const unauth = await fetch(base + '/mcp', {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'verify', version: '1' } },
  }),
});
check('unauthenticated POST /mcp is 401', unauth.status === 401, `status ${unauth.status}`);

const challenge = unauth.headers.get('www-authenticate');
check('401 carries WWW-Authenticate', !!challenge, String(challenge));
check(
  'challenge names a resource_metadata document',
  !!challenge && /resource_metadata="[^"]+"/.test(challenge),
  String(challenge)
);

// --- follow the challenge, exactly as a client would ----------------------
const named = challenge?.match(/resource_metadata="([^"]+)"/)?.[1];
if (named) {
  const path = named.startsWith(base) ? named.slice(base.length) : new URL(named).pathname;
  const doc = await getJson(path);
  check(`the named document ${path} is 200`, doc.status === 200, `status ${doc.status}`);

  // RFC 9728 §3.3: `resource` must equal the identifier the URL was derived
  // from, or a conforming client discards the document.
  const derivedFrom = named.replace('/.well-known/oauth-protected-resource', '');
  check(
    'its resource matches the identifier the URL was derived from',
    doc.body?.resource === derivedFrom,
    `resource=${doc.body?.resource} expected=${derivedFrom}`
  );
  check(
    'it names an authorization server',
    Array.isArray(doc.body?.authorization_servers) && doc.body.authorization_servers.length > 0,
    JSON.stringify(doc.body?.authorization_servers)
  );
}

// --- every derived URL a client might construct must resolve --------------
const endpointDocs = [];
for (const path of ['/mcp', '/sse']) {
  const doc = await getJson(`/.well-known/oauth-protected-resource${path}`);
  endpointDocs.push({ path, doc });
  check(`derived document for ${path} is 200`, doc.status === 200, `status ${doc.status}`);
  check(
    `derived document for ${path} is self-consistent`,
    doc.body?.resource === `${base}${path}`,
    `resource=${doc.body?.resource}`
  );
}

const originDoc = await getJson('/.well-known/oauth-protected-resource');
check('origin document is 200', originDoc.status === 200, `status ${originDoc.status}`);
check(
  'origin document is self-consistent',
  originDoc.body?.resource === base,
  `resource=${originDoc.body?.resource}`
);

// --- can it actually start a login? ---------------------------------------
// validateConfig() only warns when INSFORGE_CLIENT_ID/SECRET are missing, so a
// server with no OAuth credentials starts, passes health checks and serves every
// discovery document above — and then cannot log anyone in. /oauth/authorize
// checks its credentials before it validates parameters, so a bare request
// separates the two without needing a registered client:
//   500 server_error  -> credentials missing
//   400 invalid_request -> configured, just called without parameters
const authorize = await getJson('/oauth/authorize');
check(
  'OAuth credentials are configured',
  authorize.status !== 500,
  authorize.body?.error_description || `status ${authorize.status}`
);
check(
  'the authorize endpoint is reachable and validating',
  authorize.status === 400 || authorize.status === 302,
  `status ${authorize.status}`
);

// --- follow the chain to whichever AS the resources name -------------------
// This is the client's next hop, so it gets checked whether the AS is us or the
// platform. RFC 8414 §3.1 derives the URL the same way RFC 9728 does — insert
// the well-known segment between host and path — and §3.3 requires `issuer` to
// equal the identifier it was derived from.
//
// Worth checking rather than assuming: every implementation looked at while
// writing this got that rule wrong in one direction or another.
function asMetadataUrl(issuer) {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/$/, '');
  return `${u.origin}/.well-known/oauth-authorization-server${path}`;
}

/** A URL we are willing to follow. Anything else is a failure, not a skip. */
function parseIssuer(issuer) {
  if (typeof issuer !== 'string' || issuer.length === 0) {
    return { error: `not a string: ${JSON.stringify(issuer)}` };
  }
  let u;
  try {
    u = new URL(issuer);
  } catch {
    return { error: `unparseable: ${issuer}` };
  }
  // Discovery over plaintext leaks the whole chain and is trivially spoofable.
  // Loopback is exempt so this script can be pointed at a local server.
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !loopback) {
    return { error: `not https: ${issuer}` };
  }
  return { url: u };
}

// Each document names its own authorization server, and they are allowed to
// differ. Checking only the origin document's list would miss a /mcp document
// pointing somewhere else entirely — which is exactly the kind of skew this
// script exists to catch.
const issuerSources = new Map();
for (const { label, body } of [
  { label: 'origin document', body: originDoc.body },
  ...endpointDocs.map(({ path, doc }) => ({ label: `${path} document`, body: doc.body })),
]) {
  const list = body?.authorization_servers;
  check(
    `the ${label} names authorization servers as an array`,
    Array.isArray(list) && list.length > 0,
    JSON.stringify(list)
  );
  if (!Array.isArray(list)) continue;
  for (const issuer of list) {
    const key = typeof issuer === 'string' ? issuer : JSON.stringify(issuer);
    if (!issuerSources.has(key)) issuerSources.set(key, { issuer, labels: [] });
    issuerSources.get(key).labels.push(label);
  }
}

const offTargetHosts = new Set();

for (const { issuer, labels } of issuerSources.values()) {
  const parsed = parseIssuer(issuer);
  if (parsed.error) {
    // A malformed issuer is a failure of the box under test — it published it.
    check(`authorization server named by ${labels.join(', ')} is a usable https URL`, false, parsed.error);
    continue;
  }
  check(`authorization server named by ${labels.join(', ')} is a usable https URL`, true, issuer);

  // The decisive question: is this host the deployment we were asked about?
  const scope = parsed.url.origin === baseOrigin ? 'target' : 'external';
  if (scope === 'external') offTargetHosts.add(parsed.url.origin);

  const url = asMetadataUrl(issuer);
  let doc;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    doc = { status: res.status, body: await res.json().catch(() => undefined) };
  } catch (error) {
    doc = { status: `ERR ${error}`, body: undefined };
  }

  check(`AS metadata for ${issuer} is 200 at its derived URL`, doc.status === 200, `${url} → ${doc.status}`, scope);
  check(
    `AS metadata for ${issuer} declares a matching issuer`,
    doc.body?.issuer === issuer,
    `issuer=${doc.body?.issuer} expected=${issuer}`,
    scope
  );
  for (const field of ['authorization_endpoint', 'token_endpoint']) {
    check(`AS metadata for ${issuer} advertises ${field}`, !!doc.body?.[field], String(doc.body?.[field]), scope);
  }
}

// --- report ---------------------------------------------------------------
for (const r of results) {
  if (r.scope === 'external') {
    // Never printed as PASS. A pass here says the OTHER host is healthy, which
    // is the reading that made this gate look four checks better than it was.
    console.log(`OFF-TARGET  ${r.name}  — ${r.ok ? 'ok' : 'FAILED'}, but describes another host: ${r.detail}`);
    continue;
  }
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok ? '' : `  — ${r.detail}`}`);
}

const scored = results.filter((r) => r.scope === 'target');
console.log(`\n${scored.length - failed}/${scored.length} checks passed against ${base}`);

const external = results.filter((r) => r.scope === 'external');
if (external.length > 0) {
  console.log(
    `\n${external.length} check(s) describe ${[...offTargetHosts].join(', ')} and were NOT counted.\n` +
      `  Those documents point away from the deployment under test, so their answers\n` +
      `  say nothing about it. Before a DNS cutover this is expected: the new box\n` +
      `  advertises the final hostname, which still resolves to the old one.\n` +
      `  Re-run against the final hostname after propagation to actually gate it.`
  );
}

if (!expectedVersion) {
  console.log(
    `\nNo expected version given, so the strongest check did not run.\n` +
      `  A container serving the right name at the wrong version passes every\n` +
      `  other assertion here. Pass it: verify-deploy.mjs ${base} <version>`
  );
}

process.exit(failed === 0 ? 0 : 1);
