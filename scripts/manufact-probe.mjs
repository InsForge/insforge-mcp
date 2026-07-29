#!/usr/bin/env node
/**
 * Answers one question and nothing else: does the host's edge pass our paths
 * through to the container?
 *
 * insforge-mcp serves OAuth on /oauth/*, discovery on /.well-known/*, and MCP
 * on /mcp and /sse. A platform built around mcp-use servers may route only
 * /mcp and /sse, in which case moving there is a blocker rather than a config
 * item — and nobody knows, because we have never had a successful boot.
 *
 * That question has been stuck behind Redis, and it does not need Redis. Or
 * the platform credentials. Or a build. Node's standard library and PORT,
 * nothing else, so it starts anywhere a container starts.
 *
 *   start command:  node scripts/manufact-probe.mjs
 *   then:           curl https://<host>/probe
 *
 * /probe reports every path that reached this process. Anything missing from
 * that list was answered or dropped by the edge before we ever saw it.
 */
import http from 'node:http';

const PORT = Number(process.env.PORT) || 3000;

// The exact paths a real client walks, in the order it walks them.
const REQUIRED = [
  '/health',
  '/.well-known/oauth-protected-resource',
  '/.well-known/oauth-protected-resource/mcp',
  '/.well-known/oauth-authorization-server',
  '/oauth/register',
  '/oauth/authorize',
  '/oauth/token',
  '/oauth/callback',
  '/mcp',
  '/sse',
];

const seen = new Map();

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, 'http://placeholder');
  if (pathname !== '/probe') {
    const key = `${req.method} ${pathname}`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
    console.log(`[probe] reached container: ${key}`);
  }

  res.setHeader('content-type', 'application/json');

  if (pathname === '/probe') {
    const reached = new Set([...seen.keys()].map((k) => k.split(' ')[1]));
    const missing = REQUIRED.filter((p) => !reached.has(p));
    res.writeHead(200);
    return res.end(
      JSON.stringify(
        {
          verdict:
            missing.length === 0
              ? 'every probed path reached the container'
              : 'some paths never arrived — curl them first, then re-read this',
          missing,
          reached: Object.fromEntries(seen),
        },
        null,
        2
      )
    );
  }

  // Everything else: prove we received it, in a shape that cannot be confused
  // with a platform placeholder page.
  res.writeHead(200);
  res.end(JSON.stringify({ probe: 'insforge-mcp path probe', method: req.method, path: pathname }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[probe] listening on 0.0.0.0:${PORT}`);
  console.log('[probe] curl these, then GET /probe for the verdict:');
  for (const p of REQUIRED) console.log(`[probe]   ${p}`);
});
