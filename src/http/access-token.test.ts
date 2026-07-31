import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import {
  issueAccessToken,
  readAccessToken,
  ACCESS_TOKEN_TTL_SECONDS,
  accessTokenLifetimeSeconds,
  MAX_ACCESS_TOKEN_LENGTH,
  type AccessTokenPayload,
} from './access-token.js';
import { deriveAuthStateKey } from './config.js';

/**
 * The most valuable envelope we issue, and it shipped without a test file.
 * That is the gap this closes — the fields it carries were argued about in
 * review and pinned nowhere.
 */

const key = createHmac('sha256', 'a-test-secret').update('mcp-access-token-v1').digest();
const otherKey = createHmac('sha256', 'a-different-secret').update('mcp-access-token-v1').digest();
const T0 = 1_700_000_000_000;

const payload: AccessTokenPayload = {
  userId: 'user_1',
  platformAccessToken: 'eyJ.a-platform-jwt.sig',
  projectId: 'proj_1',
};

describe('the access token', () => {
  it('comes back as what went in', () => {
    const token = issueAccessToken(payload, key, T0);
    expect(readAccessToken(token, key, T0)).toEqual(payload);
  });

  it('carries ONLY platform-issued, bounded fields', () => {
    // The test Max's finding earns. `projectName` was in here, a project name
    // is `z.string().min(2)` upstream with no `.max`, and it rode inside every
    // token issued for that project — so one org member's 10k-character name
    // minted an unusable token for every other member.
    //
    // Asserting the exact key set rather than the absence of one name: the
    // defect was a class (caller-influenced data in a credential), and
    // `organizationId`, `accessHost` and `userEmail` were in the same class,
    // three of them read from the payload by nothing at all.
    const token = issueAccessToken(payload, key, T0);
    const opened = readAccessToken(token, key, T0)!;
    expect(Object.keys(opened).sort()).toEqual(['platformAccessToken', 'projectId', 'userId']);
  });

  it('refuses to issue a token no proxy would carry', () => {
    // The belt. Bounded by construction is what the payload is FOR, so this
    // should never fire in production — it fires when someone adds a field that
    // is not bounded, which is precisely the mistake that has now been made
    // three times in one day on three different envelopes.
    const huge = { ...payload, platformAccessToken: 'x'.repeat(MAX_ACCESS_TOKEN_LENGTH) };
    expect(() => issueAccessToken(huge, key, T0)).toThrow(/Refusing to issue an access token/);
  });

  it('does not print the payload when it refuses', () => {
    // A length is enough to act on. This message reaches logs.
    const secret = 'super-secret-platform-token-'.repeat(200);
    try {
      issueAccessToken({ ...payload, platformAccessToken: secret }, key, T0);
      throw new Error('expected a refusal');
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
      expect((error as Error).message).toMatch(/limit 4096/);
    }
  });

  it('leaves realistic room: a real token is far under the cap', () => {
    // If this ever gets close, the cap is doing nothing and the number needs
    // re-deriving from a fresh measurement of the chain, not raising.
    const token = issueAccessToken(payload, key, T0);
    expect(token.length).toBeLessThan(MAX_ACCESS_TOKEN_LENGTH / 2);
  });

  it('is null, never a throw, for anything that is not ours', () => {
    // Every caller treats "not our token" as an ordinary 401, and #95 is what
    // happens when one of these paths throws instead: a 500 with no
    // WWW-Authenticate, which tells an MCP client to give up rather than to
    // sign in again.
    expect(readAccessToken('', key, T0)).toBeNull();
    expect(readAccessToken('not-a-token', key, T0)).toBeNull();
    expect(readAccessToken('v1.STALE_FROM_AN_EARLIER_FORMAT', key, T0)).toBeNull();
    expect(readAccessToken('v2.' + 'A'.repeat(80), key, T0)).toBeNull();
  });

  it('is null under a different key, so rotation signs everyone out', () => {
    // The stated and only revocation mechanism for the sealed values: rotating
    // INSFORGE_CLIENT_SECRET. Worth a test because it is also the operational
    // cost Max flagged — client ids, auth states and access tokens all die at
    // once.
    const token = issueAccessToken(payload, key, T0);
    expect(readAccessToken(token, otherKey, T0)).toBeNull();
  });

  it('is null once tampered with', () => {
    const token = issueAccessToken(payload, key, T0);
    const flipped = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
    expect(readAccessToken(flipped, key, T0)).toBeNull();
  });

  it('expires 24 hours out, not 30 days', () => {
    // The binding it replaced lived 30 days and refreshed on use. A value that
    // cannot be revoked directly should not live for a month — the TTL IS the
    // revocation window for the token itself, so a shortening here is a
    // security property and a lengthening needs an argument.
    const token = issueAccessToken(payload, key, T0);
    const ttlMs = ACCESS_TOKEN_TTL_SECONDS * 1000;
    expect(readAccessToken(token, key, T0 + ttlMs - 1)).toEqual(payload);
    expect(readAccessToken(token, key, T0 + ttlMs)).toBeNull();
    expect(ACCESS_TOKEN_TTL_SECONDS).toBe(24 * 60 * 60);
  });

  it('is sealed, not signed: the platform token is not readable from it', () => {
    // The reason this is AES-GCM and a client id is an HMAC. A
    // signed-but-readable bearer would publish a platform credential to anyone
    // who saw the header — including our own logs.
    const token = issueAccessToken(payload, key, T0);
    const body = Buffer.from(token.slice('v1.'.length), 'base64url').toString('utf8');
    expect(token).not.toContain(payload.platformAccessToken);
    expect(body).not.toContain(payload.platformAccessToken);
    expect(body).not.toContain('proj_1');
  });

  it('uses a key that is not the auth-state key', () => {
    // Same secret, different label. A token sealed for one purpose must not
    // open under another, or the domain separation is decorative.
    const token = issueAccessToken(payload, key, T0);
    expect(readAccessToken(token, deriveAuthStateKey('a-test-secret'), T0)).toBeNull();
  });
});

describe('the advertised lifetime', () => {
  /**
   * The PR said "24h or the platform token's expiry, whichever is sooner"; the
   * code returned a flat 24h. When the platform token dies first, a client that
   * believes the larger number keeps retrying a credential we already know is
   * dead instead of signing in again.
   */

  const jwt = (claims: object) =>
    ['eyJhbGciOiJIUzI1NiJ9', Buffer.from(JSON.stringify(claims)).toString('base64url'), 'sig'].join('.');

  it('is our TTL when the platform token outlives it', () => {
    const p = { ...payload, platformAccessToken: jwt({ exp: T0 / 1000 + 90_000 }) };
    expect(accessTokenLifetimeSeconds(p, T0)).toBe(ACCESS_TOKEN_TTL_SECONDS);
  });

  it('is the platform token when IT expires first', () => {
    const p = { ...payload, platformAccessToken: jwt({ exp: T0 / 1000 + 7200 }) };
    expect(accessTokenLifetimeSeconds(p, T0)).toBe(7200);
  });

  it('never goes negative for an already-expired platform token', () => {
    // `expires_in: -400` is not something any client is prepared to read.
    const p = { ...payload, platformAccessToken: jwt({ exp: T0 / 1000 - 400 }) };
    expect(accessTokenLifetimeSeconds(p, T0)).toBe(0);
  });

  it('falls back to our TTL for anything that is not a readable JWT', () => {
    // A token we cannot parse is not evidence of anything. Opaque strings,
    // wrong segment count, and unparseable payloads all land here.
    for (const t of ['opaque-token', 'a.b', 'a.b.c.d', 'x.!!!not-base64-json!!!.y']) {
      expect(accessTokenLifetimeSeconds({ ...payload, platformAccessToken: t }, T0))
        .toBe(ACCESS_TOKEN_TTL_SECONDS);
    }
  });

  it('falls back when the JWT has no numeric exp', () => {
    for (const claims of [{}, { exp: 'soon' }, { exp: null }]) {
      expect(accessTokenLifetimeSeconds({ ...payload, platformAccessToken: jwt(claims) }, T0))
        .toBe(ACCESS_TOKEN_TTL_SECONDS);
    }
  });

  it('does not verify the platform token, and cannot be tricked into a LONGER life', () => {
    // We deliberately read an unverified claim. That is safe in exactly one
    // direction: a forged exp can only shorten what we advertise, never extend
    // it past our own ceiling.
    const forged = { ...payload, platformAccessToken: jwt({ exp: T0 / 1000 + 10 * 365 * 86400 }) };
    expect(accessTokenLifetimeSeconds(forged, T0)).toBe(ACCESS_TOKEN_TTL_SECONDS);
  });
});
