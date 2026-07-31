import { sealAuthState, openAuthState, InvalidAuthStateError } from './auth-state.js';

/**
 * The access token we hand an MCP client, as a value rather than a Redis key.
 *
 * Until now our bearer was literally a lookup key: `resolveProjectFromToken`
 * took it, read `mcp:auth:binding:<token>`, and got back everything that gave
 * it meaning. The token said nothing. Delete the store and every issued token
 * became a meaningless string — not because OAuth was missing, but because we
 * never put anything IN the token. That is why a restart signed everyone out,
 * and it is the last thing keeping Redis alive.
 *
 * So carry it. Encrypted, not signed, and for a stronger reason than the auth
 * state: this envelope holds the PLATFORM access token. A signed-but-readable
 * bearer would publish a platform credential to anyone who saw the header.
 *
 * WHAT IS DELIBERATELY NOT IN HERE: the project's API key. It is a credential
 * with its own lifetime, and sealing it would freeze it for the token's whole
 * life — so a rotated or revoked project key would keep working. It is fetched
 * per request instead, from a cache with a short fixed TTL. See
 * project-key-cache.ts for why the TTL is fixed rather than bounded by `exp`.
 *
 * REVOCATION MOVES TO THE PLATFORM, and that is the trade to understand. The
 * binding row could be deleted; a sealed token cannot. What replaces it is the
 * platform's own revocation — `validateAccessToken` checks `revoked` on every
 * call — which is where revocation was really enforced all along. The bound on
 * how stale that can be is the project-key cache TTL, which is why it is 60
 * seconds and not "until exp".
 */

export interface AccessTokenPayload {
  /** Who this is, from the platform at login. */
  userId: string;
  userEmail: string;

  /**
   * The platform access token.
   *
   * This is what makes the MCP able to act as the user without storing
   * anything — and what makes this envelope the most valuable thing we issue.
   * It is also what lets platform-level tools (list/create/switch project)
   * exist at all: they need this, not a project key.
   */
  platformAccessToken: string;

  /** The project chosen at sign-in. A per-call or per-URL project replaces
   *  this later; it is here now so nothing else has to change at once. */
  projectId: string;
  projectName: string;
  organizationId: string;
  accessHost: string;
}

/**
 * How long an issued token is accepted.
 *
 * The binding it replaces used 30 days, refreshed on use. This is deliberately
 * shorter: a value that cannot be revoked directly should not live for a month.
 * The platform token inside has its own expiry too, and whichever runs out
 * first ends the session — which is the safe direction.
 */
export const ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;

export function issueAccessToken(
  payload: AccessTokenPayload,
  key: Buffer,
  nowMs: number = Date.now()
): string {
  return sealAuthState(payload, key, nowMs, ACCESS_TOKEN_TTL_SECONDS);
}

/**
 * Recover the payload, or null.
 *
 * Null rather than a throw because every caller treats "not our token" as an
 * ordinary 401 — an expired sign-in is the common case here, not an attack,
 * and a caller that could tell the two apart would be an oracle.
 */
export function readAccessToken(token: string, key: Buffer, nowMs: number = Date.now()): AccessTokenPayload | null {
  try {
    return openAuthState<AccessTokenPayload>(token, key, nowMs);
  } catch (error) {
    if (error instanceof InvalidAuthStateError) return null;
    throw error;
  }
}
