import { describe, it, expect, beforeAll } from 'vitest';

/**
 * The CSRF binding this whole design turns on, tested directly.
 *
 * `auth-state-cookie.test.ts` covers the helpers thoroughly and the property
 * they exist to enforce not at all — the exact shape of gap this repo keeps
 * finding. So: the record is in a cookie and the handle is in the `state`
 * parameter, and one without the other must be worth nothing.
 */

// The manager derives its key from INSFORGE_CLIENT_SECRET at call time, so the
// environment has to be set before the module is imported.
process.env.INSFORGE_CLIENT_SECRET ||= 'test-secret-for-binding';

let manager: import('./oauth-manager.js').OAuthManager;

beforeAll(async () => {
  const { getOAuthManager } = await import('./oauth-manager.js');
  manager = getOAuthManager();
});

const request = {
  redirectUri: 'http://127.0.0.1:8765/callback',
  scope: 'mcp:read mcp:write',
  state: 'the-client-own-csrf-value',
  codeChallenge: 'a'.repeat(43),
  codeChallengeMethod: 'S256',
};

describe('a sealed record is only valid with its own handle', () => {
  it('opens with the handle it was issued with', async () => {
    const { handle, sealedState } = await manager.createAuthorizationState(request);
    const opened = await manager.getAuthorizationState(sealedState, handle);

    expect(opened).not.toBeNull();
    expect(opened?.redirectUri).toBe(request.redirectUri);
    expect(opened?.state).toBe(request.state);
    expect(opened?.insforgeCodeVerifier).toBeTruthy();
  });

  it(`refuses another authorization's handle`, async () => {
    // Both halves are genuinely ours; they just belong to different sign-ins.
    // This is the case the state parameter exists to catch, and a cookie
    // without the check would accept it.
    const a = await manager.createAuthorizationState(request);
    const b = await manager.createAuthorizationState(request);

    expect(await manager.getAuthorizationState(a.sealedState, b.handle)).toBeNull();
    expect(await manager.getAuthorizationState(b.sealedState, a.handle)).toBeNull();
  });

  it('refuses a fabricated handle', async () => {
    const { sealedState } = await manager.createAuthorizationState(request);
    for (const wrong of ['', '0'.repeat(32), 'not-a-handle', 'undefined']) {
      expect(await manager.getAuthorizationState(sealedState, wrong)).toBeNull();
    }
  });

  it('refuses a cookie that is not ours, whatever handle is offered', async () => {
    const { handle } = await manager.createAuthorizationState(request);
    for (const junk of ['', 'v1.AAAA', 'not-sealed-at-all']) {
      expect(await manager.getAuthorizationState(junk, handle)).toBeNull();
    }
  });

  it('gives every authorization a distinct handle and a distinct record', async () => {
    const issued = await Promise.all(
      Array.from({ length: 20 }, () => manager.createAuthorizationState(request))
    );
    expect(new Set(issued.map((i) => i.handle)).size).toBe(20);
    expect(new Set(issued.map((i) => i.sealedState)).size).toBe(20);
  });

  it('keeps the handle short enough for the column that started all this', async () => {
    const { handle } = await manager.createAuthorizationState(request);
    expect(handle.length).toBeLessThan(255);
  });

  it('does not carry the client id, which is what busted the cookie bound', async () => {
    const { sealedState, handle } = await manager.createAuthorizationState(request);
    const opened = await manager.getAuthorizationState(sealedState, handle);
    expect(opened).not.toBeNull();
    expect(opened as unknown as Record<string, unknown>).not.toHaveProperty('clientId');
  });
});
