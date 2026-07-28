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

function check(name, ok, detail) {
  results.push({ name, ok, detail });
  if (!ok) failed++;
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
for (const path of ['/mcp', '/sse']) {
  const doc = await getJson(`/.well-known/oauth-protected-resource${path}`);
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

// --- follow the chain to whichever AS the resource names ------------------
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

const authServers = originDoc.body?.authorization_servers ?? [];
check('the resource names at least one authorization server', authServers.length > 0, JSON.stringify(authServers));

for (const issuer of authServers) {
  const url = asMetadataUrl(issuer);
  let doc;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    doc = { status: res.status, body: await res.json().catch(() => undefined) };
  } catch (error) {
    doc = { status: `ERR ${error}`, body: undefined };
  }

  check(`AS metadata for ${issuer} is 200 at its derived URL`, doc.status === 200, `${url} → ${doc.status}`);
  check(
    `AS metadata for ${issuer} declares a matching issuer`,
    doc.body?.issuer === issuer,
    `issuer=${doc.body?.issuer} expected=${issuer}`
  );
  for (const field of ['authorization_endpoint', 'token_endpoint']) {
    check(`AS metadata for ${issuer} advertises ${field}`, !!doc.body?.[field], String(doc.body?.[field]));
  }
}

// --- report ---------------------------------------------------------------
for (const r of results) {
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok ? '' : `  — ${r.detail}`}`);
}
console.log(`\n${results.length - failed}/${results.length} checks passed against ${base}`);
process.exit(failed === 0 ? 0 : 1);
