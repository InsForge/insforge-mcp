#!/usr/bin/env node
/**
 * Does every platform path we call actually exist?
 *
 * The revoke bug was a 404: the code called `/oauth/v1/revoke` where the
 * platform serves `/api/oauth/v1/revoke`. It would have failed one hundred
 * percent of the time in production, and nothing caught it — a stub answers
 * whatever path the stub was written for, unit tests never leave the process,
 * and the production probes that did run happened to exercise other routes.
 * It was found by hand, while moving the call for an unrelated reason.
 *
 * So this asks the only question a stub cannot: is this path a route the
 * platform knows? It does not need credentials and does not need a login,
 * because the platform distinguishes the two cases by status:
 *
 *   401 / 400 / 403   the route exists and refused us. Correct.
 *   404               the route does not exist. A typo that ships.
 *
 * Deliberately NOT a health check — it says nothing about whether the platform
 * is well, only whether we are calling names it has. Nine seconds, no secrets,
 * safe to run in CI on every push.
 *
 *   node scripts/verify-platform-paths.mjs [apiBase]
 */

const BASE = (process.argv[2] || process.env.INSFORGE_API_BASE || 'https://api.insforge.dev').replace(
  /\/+$/,
  ''
);

// Every platform path the server calls. A `:id` segment is filled with a
// well-formed value that no tenant owns — the point is the route, not the row.
const NOBODY = '00000000-0000-0000-0000-000000000000';
const PATHS = [
  { method: 'GET', path: '/auth/v1/profile', from: 'insforge-api.ts validateToken' },
  { method: 'GET', path: '/organizations/v1', from: 'insforge-api.ts getAllUserProjects' },
  { method: 'GET', path: `/organizations/v1/${NOBODY}/projects`, from: 'insforge-api.ts' },
  { method: 'GET', path: `/projects/v1/${NOBODY}`, from: 'insforge-api.ts getProject' },
  { method: 'GET', path: `/projects/v1/${NOBODY}/access-api-key`, from: 'insforge-api.ts' },
  { method: 'GET', path: '/api/oauth/v1/authorize', from: 'server.ts /oauth/authorize' },
  { method: 'POST', path: '/api/oauth/v1/token', from: 'insforge-api.ts exchangeCode' },
  { method: 'POST', path: '/api/oauth/v1/revoke', from: 'insforge-api.ts revoke' },
];

const EXISTS = new Set([200, 201, 204, 302, 400, 401, 403, 405, 422]);

const results = await Promise.all(
  PATHS.map(async (p) => {
    const started = Date.now();
    try {
      const res = await fetch(`${BASE}${p.path}`, {
        method: p.method,
        redirect: 'manual',
        headers: p.method === 'POST' ? { 'content-type': 'application/json' } : {},
        body: p.method === 'POST' ? '{}' : undefined,
        signal: AbortSignal.timeout(10_000),
      });
      return { ...p, status: res.status, ms: Date.now() - started };
    } catch (error) {
      return { ...p, status: 0, error: String(error).slice(0, 60), ms: Date.now() - started };
    }
  })
);

let bad = 0;
for (const r of results) {
  const ok = EXISTS.has(r.status);
  if (!ok) bad++;
  console.log(
    `${ok ? 'ok  ' : 'FAIL'}  ${String(r.status).padEnd(3)} ${r.method.padEnd(4)} ${r.path.padEnd(48)} ${r.from}${
      r.error ? `  ${r.error}` : ''
    }`
  );
}

console.log(
  `\n${results.length - bad}/${results.length} platform paths exist on ${BASE}` +
    (bad ? `\n${bad} route(s) the platform does not serve — a request we send will always fail.` : '')
);
process.exit(bad ? 1 : 0);
