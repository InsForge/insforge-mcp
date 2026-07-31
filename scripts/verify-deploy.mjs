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
 * Every request this script makes carries a deadline.
 *
 * It runs on a schedule and as a deploy gate, so a stalled endpoint would
 * otherwise hang until the CI runner's own timeout and the whole check report
 * would be lost — a server that never answers is a failure worth reporting,
 * not a reason to report nothing.
 */
const TIMEOUT_MS = Number(process.env.VERIFY_TIMEOUT_MS) > 0 ? Number(process.env.VERIFY_TIMEOUT_MS) : 10_000;
const deadline = () => AbortSignal.timeout(TIMEOUT_MS);

/**
 * Record an assertion.
 *
 * scope 'target'   — describes the deployment named on the command line.
 * scope 'external' — describes some other host, reported but never scored.
 *
 * "Different origin" alone is the wrong test, because it also describes a
 * resource server that legitimately delegates to a separate authorization
 * server — which is where this codebase is heading. Under that reading a real
 * failure of a real dependency prints OFF-TARGET and does not count, which
 * fails in the green direction.
 *
 * The discriminator is whether the box agrees about where it lives. Before a
 * DNS cutover it does not: reached on a temporary URL, it still publishes the
 * FINAL hostname as its own identifier, and that same hostname is what it
 * names as its authorization server — so the chain leads to the machine being
 * replaced. When its documents DO agree with the URL under test, whatever
 * they point at is the client's genuine next hop and gets scored wherever it
 * lives.
 */
function check(name, ok, detail, scope = 'target') {
  results.push({ name, ok, detail, scope });
  if (!ok && scope === 'target') failed++;
}

/** Raw fetch that yields null instead of throwing. */
async function fetchOrNull(url, init) {
  try {
    return await fetch(url, { ...init, signal: deadline() });
  } catch {
    return null;
  }
}

/** Network-level failure as a value. A box that has not finished starting is
 *  the first thing this gets pointed at on cutover day, and an unhandled
 *  fetch rejection there reads as a broken script rather than a down server. */
function unreachable(error) {
  return `unreachable (${error?.cause?.code || error?.message || error})`;
}

async function getJson(path) {
  let res;
  try {
    res = await fetch(base + path, { headers: { accept: 'application/json' }, signal: deadline() });
  } catch (error) {
    return { status: unreachable(error), body: undefined, headers: undefined };
  }
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
if (typeof health.status === 'string' && health.status.startsWith('unreachable')) {
  // Everything below would fail the same way and bury the one fact that matters.
  console.log(`FAIL  GET /health is 200  — ${health.status}`);
  console.log(`\n${base} did not answer at all. Nothing else was checked.`);
  process.exit(1);
}
// A 200 on /health proves something answered, not that WE answered.
// Manufact's gateway returns {"status":"healthy","timestamp":...} with a 200
// whether or not a container is running behind it, so a 200-only assertion is
// green against an empty deployment. Ours names itself; the placeholder cannot.
check(
  '/health is our server, not a platform placeholder',
  health.body?.server === 'insforge-mcp',
  `server=${JSON.stringify(health.body?.server)} body=${JSON.stringify(health.body)?.slice(0, 120)}`
);

// Reported unconditionally: a container serving the right name at the wrong
// build is the failure that let production sit 139 days stale, and leaving the
// version unasserted is how that stays invisible.
check(
  expectedVersion ? `/health reports version ${expectedVersion}` : '/health reports a version',
  expectedVersion ? health.body?.version === expectedVersion : !!health.body?.version,
  `got ${health.body?.version}`
);

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
const unauth = await fetchOrNull(base + '/mcp', {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'verify', version: '1' } },
  }),
});
check('unauthenticated POST /mcp is 401', unauth?.status === 401, `status ${unauth?.status ?? 'unreachable'}`);

const challenge = unauth?.headers.get('www-authenticate');
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
  // Only 400. The handler validates its parameters before it can redirect, so
  // a bare probe can never legitimately produce a 302 — accepting one would
  // quietly excuse a proxy or a route change that started answering here.
  'the authorize endpoint is reachable and validating',
  authorize.status === 400,
  `status ${authorize.status}`
);

// The two checks above are both satisfied by the argument-validation layer,
// which answers before the handler touches its client store. That is exactly
// how this script scored a PASS on a deployment where no user could log in:
// registration and authorize were both 500ing on
// `MaxRetriesPerRequestError (ioredis)`, and a parameterless probe never got
// far enough to see it.
//
// So send a request that is complete enough to reach the store. The client id
// is deliberately one that cannot exist: a server whose store is healthy looks
// it up, misses, and says so; a server whose store is unreachable cannot get
// that far. Both outcomes are 4xx-vs-5xx, and neither registers anything, so
// the script stays read-only.
//
//   400 invalid_client -> store reached, id genuinely unknown  (healthy)
//   500                -> the lookup itself failed             (broken)
const probeAuthorize = await getJson(
  '/oauth/authorize?response_type=code' +
    '&client_id=verify-deploy-probe-not-a-real-client' +
    '&redirect_uri=' + encodeURIComponent('http://127.0.0.1:33418/callback') +
    '&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' +
    '&code_challenge_method=S256' +
    '&state=verify-deploy'
);
check(
  'a fully-formed authorize request reaches the client store',
  probeAuthorize.status !== 500,
  probeAuthorize.status === 500
    ? 'authorize 500s on a complete request — the client store is unreachable, ' +
      'so no login can complete (check Redis/backing store)'
    : `status ${probeAuthorize.status}`
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

// Does the box agree about where it lives? Compared by origin, so this holds
// whichever identifier convention the resource document uses for its path.
// A box reached on a URL it does not believe is its own is the pre-cutover
// case, and only then does its authorization server point at another machine
// by accident rather than by design.
let targetKnowsItsOwnOrigin;
try {
  targetKnowsItsOwnOrigin = new URL(originDoc.body?.resource).origin === baseOrigin;
} catch {
  targetKnowsItsOwnOrigin = false;
}
check(
  'the target publishes an identifier on the origin it was reached at',
  targetKnowsItsOwnOrigin,
  `resource=${originDoc.body?.resource} reached at ${baseOrigin}`
);

for (const { issuer, labels } of issuerSources.values()) {
  const parsed = parseIssuer(issuer);
  if (parsed.error) {
    // A malformed issuer is a failure of the box under test — it published it.
    check(`authorization server named by ${labels.join(', ')} is a usable https URL`, false, parsed.error);
    continue;
  }
  check(`authorization server named by ${labels.join(', ')} is a usable https URL`, true, issuer);

  // Score it wherever it lives, UNLESS the box does not agree about its own
  // origin — that is the pre-cutover case, where the chain leads to the
  // machine being replaced rather than to a deliberate dependency.
  const sameOrigin = parsed.url.origin === baseOrigin;
  const scope = sameOrigin || targetKnowsItsOwnOrigin ? 'target' : 'external';
  if (scope === 'external') offTargetHosts.add(parsed.url.origin);

  const url = asMetadataUrl(issuer);
  let doc;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' }, signal: deadline() });
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
      `  They were excluded because this box does not agree about where it lives:\n` +
      `  reached at ${baseOrigin}, it publishes ${originDoc.body?.resource} as its own\n` +
      `  identifier, so the authorization server it names is the machine that\n` +
      `  hostname currently resolves to — not this one. That is expected before a\n` +
      `  DNS cutover. Re-run against the final hostname after propagation to gate it.\n` +
      `  A box whose documents DO agree has its authorization server scored\n` +
      `  wherever it lives, so a delegated AS still gates the deploy.`
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
