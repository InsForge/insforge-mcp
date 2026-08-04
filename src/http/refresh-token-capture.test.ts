import { describe, it, expect, beforeAll } from 'vitest';

/**
 * The platform's refresh token has to survive three sealed hops to be of any
 * use, and every one of them is a separate envelope:
 *
 *   callback  -> the auth STATE      (attachPlatformToken)
 *   picker    -> the auth CODE       (createAuthorizationCode)
 *   exchange  -> back out to us      (exchangeCode)
 *
 * Losing it at any hop looks identical from the outside — the sign-in still
 * works, and the client still dies an hour later. That is precisely the failure
 * this feature exists to remove, so it is worth pinning per hop rather than
 * trusting one end-to-end run that nobody can perform without a real account.
 */

process.env.INSFORGE_CLIENT_SECRET ||= 'test-secret-for-refresh-capture';

let manager: import('./oauth-manager.js').OAuthManager;
let openAuthState: typeof import('./auth-state.js').openAuthState;
let sealAuthState: typeof import('./auth-state.js').sealAuthState;
let authStateKey: typeof import('./config.js').authStateKey;
let authCodeKey: typeof import('./config.js').authCodeKey;

beforeAll(async () => {
  const oauth = await import('./oauth-manager.js');
  const state = await import('./auth-state.js');
  const config = await import('./config.js');
  manager = oauth.getOAuthManager();
  openAuthState = state.openAuthState;
  sealAuthState = state.sealAuthState;
  authStateKey = config.authStateKey;
  authCodeKey = config.authCodeKey;
});

const PLATFORM_REFRESH = 'platform-refresh-token-value';

async function freshState() {
  const { sealedState, handle } = await manager.createAuthorizationState({
    redirectUri: 'http://127.0.0.1:8765/callback',
    scope: 'mcp:read',
    codeChallenge: 'a'.repeat(43),
    codeChallengeMethod: 'S256',
  });
  const authState = await manager.getAuthorizationState(sealedState, handle);
  if (!authState) throw new Error('state did not open');
  return authState;
}

describe('hop 1: the callback attaches it to the auth state', () => {
  it('seals the refresh token alongside the access token', async () => {
    const sealed = manager.attachPlatformToken(await freshState(), 'access-abc', PLATFORM_REFRESH);
    const opened = openAuthState<{ platformAccessToken?: string; platformRefreshToken?: string }>(
      sealed,
      authStateKey()
    );
    expect(opened.platformAccessToken).toBe('access-abc');
    expect(opened.platformRefreshToken).toBe(PLATFORM_REFRESH);
  });

  it('does not publish it — the state travels in a cookie', async () => {
    const sealed = manager.attachPlatformToken(await freshState(), 'access-abc', PLATFORM_REFRESH);
    expect(sealed).not.toContain(PLATFORM_REFRESH);
  });

  it('stays undefined when the platform sent none', async () => {
    // Older platform builds, or a grant that does not issue one. Absence has to
    // stay absence rather than becoming the string "undefined" in the envelope.
    const sealed = manager.attachPlatformToken(await freshState(), 'access-abc');
    const opened = openAuthState<{ platformRefreshToken?: string }>(sealed, authStateKey());
    expect(opened.platformRefreshToken).toBeUndefined();
  });
});

describe('hop 3: the exchange hands it back', () => {
  // Hop 2 (createAuthorizationCode) calls the live platform to validate the
  // token, so it is driven here from the code it produces rather than mocked:
  // seal the same payload shape it seals, and assert the exchange returns the
  // field. If hop 2 ever stops sealing it, hop 3's contract still holds and
  // this test still passes — which is why hop 1 above is asserted separately.
  const redirectUri = 'http://127.0.0.1:8765/callback';
  const verifier = 'v'.repeat(64);

  async function codeCarrying(refreshToken?: string) {
    const { createHash } = await import('crypto');
    return sealAuthState(
      {
        accessToken: 'platform-access-token',
        refreshToken,
        redirectUri,
        codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
        codeChallengeMethod: 'S256',
      },
      authCodeKey(),
      Date.now(),
      5 * 60
    );
  }

  it('returns the refresh token sealed into the code', async () => {
    const result = await manager.exchangeCode(await codeCarrying(PLATFORM_REFRESH), redirectUri, verifier);
    expect(result.accessToken).toBe('platform-access-token');
    expect(result.refreshToken).toBe(PLATFORM_REFRESH);
  });

  it('returns undefined rather than throwing when the code carries none', async () => {
    // Every code issued before this change is in exactly this shape, and they
    // are valid for five more minutes at deploy time. They must still redeem.
    const result = await manager.exchangeCode(await codeCarrying(undefined), redirectUri, verifier);
    expect(result.accessToken).toBe('platform-access-token');
    expect(result.refreshToken).toBeUndefined();
  });
});
