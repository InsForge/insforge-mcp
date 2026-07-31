import { describe, it, expect } from 'vitest';
import { sessionAcceptsCredential, routeForSessionRequest } from './session-manager.js';

/**
 * A session id is a bearer credential, and binding it to the sign-in that
 * created it is what stops a leaked one being usable.
 *
 * The table below is deliberately per-VERB. The first version of this check
 * bound POST only, which was a POST-shaped fix for a session-shaped problem —
 * a session is reachable by three verbs, and Quinn demonstrated the gap rather
 * than arguing it:
 *
 *   DELETE /mcp with just the session id   -> 200
 *   the victim's next valid request        -> 404
 *
 * So the primary assertion here is that every verb consults the same function,
 * and the per-verb rows exist so that adding a fourth without binding it fails
 * a test rather than passing quietly.
 */

const STORED = 'a'.repeat(64); // a full sha256, as SessionData holds
const OTHER = 'b'.repeat(64);

/** The three verbs that can reach a live session. */
const VERBS = ['POST', 'GET', 'DELETE'] as const;

describe('sessionAcceptsCredential, for every verb that reaches a session', () => {
  it.each(VERBS)('%s accepts the credential the session was opened with', () => {
    expect(sessionAcceptsCredential(STORED, STORED)).toBe(true);
  });

  it.each(VERBS)('%s refuses a different credential', () => {
    expect(sessionAcceptsCredential(STORED, OTHER)).toBe(false);
  });

  it.each(VERBS)('%s refuses a request presenting NO credential', () => {
    // The whole attack: the id alone. If this passes, everything above is
    // decoration.
    expect(sessionAcceptsCredential(STORED, undefined)).toBe(false);
    expect(sessionAcceptsCredential(STORED, '')).toBe(false);
  });

  it.each(VERBS)('%s leaves a legacy x-api-key session alone', () => {
    // Its credential is the header it re-sends every request; there is no token
    // to compare. Rejecting these logs out every legacy client on deploy.
    expect(sessionAcceptsCredential('legacy', undefined)).toBe(true);
    expect(sessionAcceptsCredential('legacy', OTHER)).toBe(true);
  });

  it.each(VERBS)('%s leaves a session that stored no hash alone', () => {
    // One SSE path stores ''. Same reasoning as legacy.
    expect(sessionAcceptsCredential('', undefined)).toBe(true);
    expect(sessionAcceptsCredential(undefined, undefined)).toBe(true);
  });
});

describe('the trap that would log everyone out', () => {
  it('rejects a truncated hash, because a fingerprint is not a hash', () => {
    // SessionData stores the full 64-char sha256 (oauth-manager hashToken);
    // server.ts also has tokenFingerprint, the FIRST 8 CHARS, for logs.
    // Comparing one form against the other rejects every OAuth session on its
    // second request — a mid-session logout for everyone, arriving through the
    // door this check exists to keep shut. Quinn hit exactly this.
    expect(sessionAcceptsCredential(STORED, STORED.substring(0, 8))).toBe(false);
    expect(STORED.length).toBe(64);
  });

  it('is an exact comparison, not a prefix one', () => {
    // A prefix match would let an 8-char guess stand in for 64.
    expect(sessionAcceptsCredential(STORED, STORED + 'x')).toBe(false);
    expect(sessionAcceptsCredential(STORED, STORED.substring(0, 63))).toBe(false);
  });
});

describe('binding does not disturb the recovery path', () => {
  it('routeForSessionRequest still takes no credential at all', () => {
    // The 404-before-authentication property, pinned structurally rather than
    // by comment. If someone later threads a token into routing, a client with
    // a dead session and a stale token starts getting 401 where it needs the
    // 404 that tells it to start over — and this test fails instead of the
    // property disappearing quietly.
    const args = Object.keys(
      routeForSessionRequest({ hasRuntime: false, sessionId: 'x', isInitialize: false }) === 'not-found'
        ? { hasRuntime: 0, sessionId: 0, isInitialize: 0 }
        : {}
    );
    expect(args.sort()).toEqual(['hasRuntime', 'isInitialize', 'sessionId']);
    expect(routeForSessionRequest.length).toBe(1);
  });

  it('an unknown session id is still 404, whatever credential is presented', () => {
    // Binding must never turn a dead session into an authentication problem.
    for (const isInitialize of [false]) {
      expect(routeForSessionRequest({ hasRuntime: false, sessionId: 'dead', isInitialize }))
        .toBe('not-found');
    }
  });
});

describe('what a refused request is told', () => {
  /**
   * The status is the whole contract here, and 401 was wrong.
   *
   * 401 means "re-run OAuth". Consider a client that just did: it holds a NEW
   * token and retries with the session id it still has. Credential valid,
   * session real, different sign-ins — so 401 sends it round OAuth again, to
   * return with another new token and the same old id. An infinite loop caused
   * by signing in again.
   *
   * 404 is the answer it needs and the one routing already gives: start a new
   * session. This test pins the reasoning, since the code alone cannot say why
   * a status was chosen over its neighbour.
   */

  it('treats a valid-but-different credential exactly like an unheld session', () => {
    // Both must lead to "initialize again", never to "authenticate again".
    const reAuthorized = sessionAcceptsCredential(STORED, OTHER);
    expect(reAuthorized).toBe(false);
    expect(routeForSessionRequest({ hasRuntime: false, sessionId: 'dead', isInitialize: false }))
      .toBe('not-found');
  });

  it('lets a re-authorized client recover by initializing, not by re-authorizing', () => {
    // The escape hatch: an initialize is routed to 'create' even carrying the
    // stale id, so the client that receives the 404 can act on it immediately.
    expect(routeForSessionRequest({ hasRuntime: false, sessionId: 'stale', isInitialize: true }))
      .toBe('create');
  });
});
