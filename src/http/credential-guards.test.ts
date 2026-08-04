import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * The two guards that say "the platform rejected OUR credentials" rather than
 * "your sign-in expired", driven through the real routes.
 *
 * These had NO coverage. QA proved it the only way that counts: she disabled
 * each guard in turn and the suite stayed green at 314 both times. Both fixes
 * were correct and both would have reverted silently — a refactor of either
 * error-handling block puts a user back on "sign in again" during a rotation,
 * with nothing going red. This exact class had already shipped once in this
 * file, which is what makes an untested version of the fix unacceptable rather
 * than merely untidy.
 *
 * Nothing here is unit-testable: the distinction lives in a route handler, and a
 * test of an extracted helper would keep passing after someone deleted the call
 * to it — the same shape as asserting a function's return value while the
 * response drops the field. So this drives the routes, with the PLATFORM stubbed
 * and only its answer changing between cases.
 */

/** The two shapes the platform's token endpoint actually returns, verbatim. */
const PLATFORM_RESPONSES = {
  // Our client_id/secret are wrong for this deployment — a botched rotation.
  invalid_client: { status: 401, body: { error: 'invalid_client', message: 'Invalid client credentials' } },
  // Our credentials are fine; the code or refresh token is not.
  invalid_grant: { status: 400, body: { error: 'invalid_grant', message: 'Invalid authorization code' } },
} as const;

let platform: http.Server;
let platformShape: keyof typeof PLATFORM_RESPONSES = 'invalid_client';
let server: http.Server;
let baseUrl: string;
let issueRefreshToken: typeof import('./refresh-token.js').issueRefreshToken;
let refreshTokenKey: typeof import('./config.js').refreshTokenKey;

beforeAll(async () => {
  // The platform stub, on an ephemeral port, so the env can point at it before
  // the server module is imported and reads its config.
  platform = http.createServer((_req, res) => {
    const { status, body } = PLATFORM_RESPONSES[platformShape];
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => platform.listen(0, '127.0.0.1', resolve));
  const platformPort = (platform.address() as AddressInfo).port;

  process.env.INSFORGE_API_BASE = `http://127.0.0.1:${platformPort}`;
  process.env.INSFORGE_CLIENT_ID = 'test-client-id';
  process.env.INSFORGE_CLIENT_SECRET = 'test-client-secret';
  process.env.MCP_SERVER_URL = 'http://127.0.0.1';

  // Imported AFTER the env is set, and importing no longer starts a listener —
  // see the entry-point guard at the bottom of server.ts, which exists so this
  // file can exist.
  const [{ app }, refreshToken, config] = await Promise.all([
    import('./server.js'),
    import('./refresh-token.js'),
    import('./config.js'),
  ]);
  issueRefreshToken = refreshToken.issueRefreshToken;
  refreshTokenKey = config.refreshTokenKey;

  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await new Promise<void>((resolve) => platform.close(() => resolve()));
});

/** A refresh token of ours, sealed with the key this deployment derives. */
function ourRefreshToken(): string {
  return issueRefreshToken(
    { userId: 'u1', platformRefreshToken: 'platform-refresh', projectId: 'p1' },
    refreshTokenKey()
  );
}

async function postRefresh(token: string) {
  return fetch(`${baseUrl}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token }),
  });
}

/**
 * The callback needs a state the server will open, so this walks the real flow:
 * register a client, start an authorize (which sets the sealed cookie and hands
 * the platform a handle), then call back with a junk code carrying both.
 *
 * That is also exactly the container-side pre-flight from the cutover checklist
 * — the check that proves the CONTAINER holds the right secret rather than
 * proving the secret in someone's clipboard does.
 */
async function callbackWithJunkCode() {
  const registered = await fetch(`${baseUrl}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://127.0.0.1:9999/cb'] }),
  }).then((r) => r.json() as Promise<{ client_id: string }>);

  const authorize = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(registered.client_id)}` +
      `&redirect_uri=${encodeURIComponent('http://127.0.0.1:9999/cb')}` +
      `&code_challenge=${'a'.repeat(43)}&code_challenge_method=S256`,
    { redirect: 'manual' }
  );

  const cookie = (authorize.headers.get('set-cookie') ?? '').split(';')[0];
  const handle = new URL(authorize.headers.get('location') ?? '', 'http://x').searchParams.get('state');

  return fetch(`${baseUrl}/oauth/callback?code=junk&state=${encodeURIComponent(handle ?? '')}`, {
    headers: { cookie, accept: 'text/html' },
  });
}

describe('the platform rejecting OUR credentials', () => {
  it('answers the refresh grant with 503 and a Retry-After, never "sign in again"', async () => {
    platformShape = 'invalid_client';
    const response = await postRefresh(ourRefreshToken());

    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('30');

    const body = (await response.json()) as { error: string; error_description: string };
    expect(body.error).toBe('temporarily_unavailable');
    // The whole point: a wrong INSFORGE_CLIENT_SECRET must not send every
    // connected user to re-authenticate, because they all would, and every new
    // sign-in would fail the same way until an operator fixed the config.
    expect(body.error_description).not.toMatch(/sign in again/i);
  });

  it('answers the sign-in callback with 503 and a Retry-After', async () => {
    // The path a ROTATION actually hits: nobody holds a refresh token yet, so
    // everyone is doing a fresh sign-in and arrives here instead.
    platformShape = 'invalid_client';
    const response = await callbackWithJunkCode();

    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('30');
    const page = await response.text();
    expect(page).toMatch(/not with your account/i);
    expect(page).not.toMatch(/sign in again/i);
  });
});

describe('the platform declining the GRANT is still the user', () => {
  it('keeps the refresh grant on 400 invalid_grant', async () => {
    platformShape = 'invalid_grant';
    const response = await postRefresh(ourRefreshToken());

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: string; error_description: string };
    expect(body.error).toBe('invalid_grant');
    expect(body.error_description).toMatch(/sign in again/i);
  });

  it('keeps the callback on 400, distinguishable from the credential case', async () => {
    // The pair is what makes the container-side pre-flight readable: same
    // request, two platform answers, two statuses. If these ever collapse to
    // one status there is no unauthenticated way to tell a fumbled rotation
    // from a bad code on the box that matters.
    platformShape = 'invalid_grant';
    const response = await callbackWithJunkCode();

    expect(response.status).toBe(400);
    expect(response.status).not.toBe(503);
  });
});
