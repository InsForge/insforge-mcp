import { sealAuthState, openAuthState, InvalidAuthStateError } from './auth-state.js';

/**
 * The access token we hand an MCP client, as a sealed value rather than a
 * lookup key, so a restart does not sign everyone out.
 *
 * Encrypted, not signed: this envelope holds the PLATFORM access token, and a
 * signed-but-readable bearer would publish a platform credential to anyone who
 * saw the header.
 *
 * WHAT IS DELIBERATELY NOT IN HERE: the project's API key. It is a credential
 * with its own lifetime, and sealing it would freeze it for the token's whole
 * life, so a rotated or revoked project key would keep working. It is fetched
 * per request from a cache with a short fixed TTL (project-key-cache.ts).
 *
 * A sealed token cannot be deleted, so revocation is the platform's: it is
 * enforced on each project-key cache miss, when resolveProjectFromToken asks
 * the platform for project access with the platform token inside, and the
 * bound on how stale that can be is the project-key cache TTL.
 */

/**
 * EVERY FIELD IN HERE IS PLATFORM-ISSUED AND BOUNDED, or it does not go in. A
 * caller-influenced string in here is a denial of service against everyone who
 * shares the resource it names: cloud-backend's project name is
 * `z.string().trim().min(2)` with no `.max`, so a 10k-character name would mint
 * a token no `Authorization` header will carry, for every member who selects
 * that project. Display data that can be re-fetched (project name,
 * organization, access host) does not belong in a credential;
 * resolveProjectFromToken reads it off the project-key cache.
 */
export interface AccessTokenPayload {
  /** Who this is, from the platform at login. */
  userId: string;

  /**
   * The platform access token.
   *
   * This is what makes the MCP able to act as the user without storing
   * anything — and what makes this envelope the most valuable thing we issue.
   * It is also what lets platform-level tools (list/create/switch project)
   * exist at all: they need this, not a project key.
   */
  platformAccessToken: string;

  /** The project chosen at sign-in. */
  projectId: string;
}

/**
 * How long an issued token is accepted. Deliberately short: a value that
 * cannot be revoked directly should not live for a month. The platform token
 * inside has its own expiry too, and whichever runs out first ends the session.
 */
export const ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;

/**
 * The longest token we will hand out. The payload is bounded by construction,
 * so this should never fire; it exists because the platform's own access token
 * inside is not ours to bound.
 *
 * Measured against the real chain (Cloudflare, the Fly proxy, Node's 16KB
 * default): 15512 chars accepted, 15573 chars rejected with 431. This payload
 * mints ~1250 chars, so 4096 is ~3.3x the real token and is reached only when
 * the platform's token passes ~2950 chars — far enough away that tripping it
 * means something changed, and far enough below 15512 that the refusal happens
 * here, where it is explained, rather than at a proxy that will not say why.
 *
 * It THROWS rather than truncating or warning. The failure lands at sign-in,
 * in the project-selection handler (createAuthorizationCode mints the token
 * before sealing the code), whose catch answers 500 with a `server_error` JSON
 * body carrying this message instead of redirecting with a code. On a refresh
 * grant the same throw escapes the token endpoint unhandled, so Express
 * answers 500 there. The alternative is a token every proxy silently refuses
 * to carry, surfacing later as a client that cannot connect for reasons
 * nothing logs.
 */
export const MAX_ACCESS_TOKEN_LENGTH = 4096;

/**
 * How long this token is ACTUALLY good for, in seconds: our TTL or the
 * platform token's remaining life, whichever is sooner. A flat 24h would have
 * a client keep retrying a credential we already know is dead.
 *
 * The platform token is a JWT, so its `exp` is readable. We do NOT verify it:
 * it is not ours to verify, and a forged one could only SHORTEN what we
 * advertise. Anything unreadable falls back to our own TTL.
 */
export function accessTokenLifetimeSeconds(
  payload: AccessTokenPayload,
  nowMs: number = Date.now()
): number {
  const platformExp = jwtExpirySeconds(payload.platformAccessToken);
  if (platformExp === null) return ACCESS_TOKEN_TTL_SECONDS;

  const platformRemaining = Math.floor(platformExp - nowMs / 1000);
  // Never negative: an already-expired platform token means zero life left, and
  // `expires_in: -400` is not something any client is prepared to read.
  return Math.max(0, Math.min(ACCESS_TOKEN_TTL_SECONDS, platformRemaining));
}

/** The `exp` claim, or null for anything that is not a readable JWT. */
function jwtExpirySeconds(token: string): number | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof claims?.exp === 'number' && Number.isFinite(claims.exp) ? claims.exp : null;
  } catch {
    return null;
  }
}

export function issueAccessToken(
  payload: AccessTokenPayload,
  key: Buffer,
  nowMs: number = Date.now()
): string {
  const token = sealAuthState(payload, key, nowMs, ACCESS_TOKEN_TTL_SECONDS);

  if (token.length > MAX_ACCESS_TOKEN_LENGTH) {
    // Deliberately does not print the token or the payload: this is the most
    // valuable envelope we issue and a length is enough to act on.
    throw new Error(
      `Refusing to issue an access token of ${token.length} characters ` +
        `(limit ${MAX_ACCESS_TOKEN_LENGTH}). A token this size will be rejected by proxies ` +
        'in the request path, so issuing it would produce a client that cannot connect and ' +
        'no explanation. Something has been added to the sealed payload that is not bounded.'
    );
  }

  return token;
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
