import { sealAuthState, openAuthState, InvalidAuthStateError } from './auth-state.js';

/**
 * The refresh token we hand an MCP client.
 *
 * We have never issued one. `/oauth/token` answers `refresh_token` with
 * `unsupported_grant_type`, and the platform's own refresh token — which it
 * returns to us at every code exchange — is read into a response type and
 * dropped on the floor. The consequence is not subtle: the platform's access
 * token lives ONE HOUR, our envelope advertises whichever is sooner, so every
 * connected client dies after an hour and the only way back is a browser.
 *
 * For a CLI on the user's own machine that is an annoyance. For a hosted
 * connector — a client that signed in once, in someone else's browser, and now
 * runs unattended — it is a broken integration.
 *
 * Same envelope as the access token and for the same reason: encrypted rather
 * than signed, because it carries a platform credential and a readable bearer
 * would publish it to anyone who saw it. Its own key, its own label, no
 * computable relationship to the other four.
 */
export interface RefreshTokenPayload {
  /** Who this is, from the platform at login. Carried so a refresh can mint an
   *  access token payload without a second round trip. */
  userId: string;

  /**
   * The PLATFORM's refresh token — the thing we currently throw away.
   *
   * Not the access token. This is the only field that distinguishes this
   * envelope from the one next door, and mixing them up would mean handing a
   * month-long credential to code that expects an hour-long one.
   */
  platformRefreshToken: string;

  /** The project chosen at sign-in, so a refreshed access token lands the user
   *  where they were rather than back at the picker. */
  projectId: string;
}

/**
 * How long we will accept a refresh token.
 *
 * Thirty days, and that number is the platform's rather than a preference:
 * `REFRESH_TOKEN_EXPIRY` in the platform's oauth service is `30 * 24 * 3600`,
 * so accepting ours for longer would advertise a life the credential inside
 * does not have — the exact mismatch that made the access token advertise 24h
 * while dying in one.
 *
 * The platform does NOT rotate on use ("keep same refresh token" in its refresh
 * path), so one issued token stays good for its whole window and we do not have
 * to reason about a rotation race across concurrent refreshes.
 */
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * A bound on what we will issue, for the same reason as the access token's —
 * with one difference worth stating, since it is why this number is not the
 * same one.
 *
 * A refresh token travels in a POST body, never in a header or a URL, so the
 * 8KB request line and the 16KB header limit that constrain the access token do
 * not apply here. What still applies is that an unbounded envelope means an
 * unbounded thing we hand out, and the payload is ours rather than the
 * caller's, so exceeding this is a bug in us and not a big request.
 */
export const MAX_REFRESH_TOKEN_LENGTH = 8192;

export function issueRefreshToken(
  payload: RefreshTokenPayload,
  key: Buffer,
  nowMs: number = Date.now()
): string {
  const token = sealAuthState(payload, key, nowMs, REFRESH_TOKEN_TTL_SECONDS);

  if (token.length > MAX_REFRESH_TOKEN_LENGTH) {
    // No token and no payload in the message: this envelope is worth more than
    // the access token's, and a length is enough to act on.
    throw new Error(
      `Refusing to issue a refresh token of ${token.length} characters ` +
        `(limit ${MAX_REFRESH_TOKEN_LENGTH}). Something has been added to the sealed payload ` +
        'that is not bounded.'
    );
  }

  return token;
}

/**
 * Recover the payload, or null.
 *
 * Null rather than a throw, matching `readAccessToken`: every caller turns "not
 * our token" into `invalid_grant`, an expired refresh is the ordinary case
 * rather than an attack, and a caller able to tell expired from forged would be
 * an oracle.
 */
export function readRefreshToken(
  token: string,
  key: Buffer,
  nowMs: number = Date.now()
): RefreshTokenPayload | null {
  try {
    return openAuthState<RefreshTokenPayload>(token, key, nowMs);
  } catch (error) {
    if (error instanceof InvalidAuthStateError) return null;
    throw error;
  }
}
