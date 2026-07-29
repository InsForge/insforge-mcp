#!/usr/bin/env node
/**
 * Drives a REAL MCP client through the REAL OAuth flow against a deployment,
 * and calls a real tool at the end.
 *
 *   node scripts/verify-handshake.mjs https://mcp.insforge.dev
 *
 * verify-deploy.mjs checks that the discovery documents are right. This checks
 * the thing they exist for: that a client can actually connect, log in, and
 * list tools. Those are different questions — every document can be perfect
 * and the handshake still fail on the callback, the code exchange, or the
 * project lookup.
 *
 * It uses the same SDK a real client uses, so a pass here means a real client
 * works, and a failure names the stage that broke rather than "it didn't work".
 *
 * One human step: a browser sign-in, because that is what OAuth is. Everything
 * either side of it is automatic.
 */
import http from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const target = (process.argv[2] || '').replace(/\/$/, '');
if (!target) {
  console.error('usage: verify-handshake.mjs <base-url>   e.g. https://mcp.insforge.dev');
  process.exit(2);
}

const CALLBACK_PORT = Number(process.env.HANDSHAKE_PORT) || 8765;
const CALLBACK_URL = `http://127.0.0.1:${CALLBACK_PORT}/callback`;
const TIMEOUT_MS = Number(process.env.HANDSHAKE_TIMEOUT_MS) || 5 * 60 * 1000;

let stage = 'startup';
const mark = (s, detail) => {
  stage = s;
  console.log(`\n[${s}]${detail ? ` ${detail}` : ''}`);
};

/** Resolves with the authorization code the browser is redirected back with. */
function waitForCallback() {
  let resolve, reject;
  const promise = new Promise((res, rej) => ((resolve = res), (reject = rej)));
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${CALLBACK_PORT}`);
    if (url.pathname !== '/callback') {
      res.writeHead(404).end();
      return;
    }
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(code ? 'Authorized. You can close this tab.' : `Authorization failed: ${error}`);
    server.close();
    if (code) resolve(code);
    else reject(new Error(`authorization returned error=${error}`));
  });
  server.listen(CALLBACK_PORT, '127.0.0.1');
  const timer = setTimeout(() => {
    server.close();
    reject(new Error(`no callback within ${TIMEOUT_MS / 1000}s`));
  }, TIMEOUT_MS);
  timer.unref();
  return { promise, close: () => server.close() };
}

// In-memory only. This is a test client; nothing it holds should outlive the run.
const store = {};
const provider = {
  get redirectUrl() {
    return CALLBACK_URL;
  },
  get clientMetadata() {
    return {
      client_name: 'insforge-mcp handshake check',
      redirect_uris: [CALLBACK_URL],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
  },
  clientInformation: () => store.client,
  saveClientInformation: (info) => {
    store.client = info;
    console.log(`      registered client_id=${info.client_id}`);
  },
  tokens: () => store.tokens,
  saveTokens: (t) => {
    store.tokens = t;
    console.log(`      received ${t.token_type || 'token'}, expires_in=${t.expires_in ?? 'unset'}`);
  },
  saveCodeVerifier: (v) => {
    store.verifier = v;
  },
  codeVerifier: () => store.verifier,
  redirectToAuthorization: (url) => {
    store.authorizeUrl = url.toString();
  },
};

const fail = (error) => {
  console.error(`\nFAILED at [${stage}]: ${error?.message || error}`);
  console.error('\nThe stage name is the useful part — everything before it worked.');
  process.exit(1);
};

const run = async () => {
  mark('discovery + registration', `against ${target}`);
  const client = new Client({ name: 'insforge-handshake', version: '1.0.0' }, { capabilities: {} });
  const url = new URL(`${target}/mcp`);

  let transport = new StreamableHTTPClientTransport(url, { authProvider: provider });
  const listener = waitForCallback();

  try {
    await client.connect(transport);
    // Already authorized (a token was somehow present) — unusual but not an error.
  } catch (error) {
    if (error?.constructor?.name !== 'UnauthorizedError') {
      listener.close();
      return fail(error);
    }

    if (!store.authorizeUrl) {
      listener.close();
      return fail(new Error('client never produced an authorization URL'));
    }

    mark('browser sign-in', 'ONE human step — open this, sign in, pick the project:');
    console.log(`\n  ${store.authorizeUrl}\n`);
    console.log(`  waiting for the redirect back to ${CALLBACK_URL} ...`);

    let code;
    try {
      code = await listener.promise;
    } catch (e) {
      return fail(e);
    }

    mark('code exchange', 'swapping the authorization code for a token');
    try {
      await transport.finishAuth(code);
    } catch (e) {
      return fail(e);
    }

    mark('connect', 'initialize, with the token');
    transport = new StreamableHTTPClientTransport(url, { authProvider: provider });
    try {
      await client.connect(transport);
    } catch (e) {
      return fail(e);
    }
  }

  mark('tools/list', 'what the server actually offers');
  const { tools } = await client.listTools();
  console.log(`      ${tools.length} tools`);
  if (tools.length === 0) return fail(new Error('connected, but the server registered no tools'));
  for (const t of tools.slice(0, 5)) console.log(`      - ${t.name}`);
  if (tools.length > 5) console.log(`      ... and ${tools.length - 5} more`);

  console.log(`\nPASS — a real MCP client signed in and listed ${tools.length} tools from ${target}`);
  console.log('This is the handshake bar. Discovery being correct is necessary, not sufficient.');
  await transport.close().catch(() => {});
  process.exit(0);
};

run().catch(fail);
