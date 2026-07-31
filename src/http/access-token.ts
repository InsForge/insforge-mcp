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

/**
 * EVERY FIELD IN HERE IS PLATFORM-ISSUED AND BOUNDED. That is a property to
 * preserve, not a coincidence, and it was not true when this file was first
 * written.
 *
 * The first version also carried `projectName`, `organizationId`, `accessHost`
 * and `userEmail`. Max found the hole in `projectName`: cloud-backend's
 * `createProjectSchema` is `z.string().trim().min(2)` — a `.min` with no
 * `.max` — so a project name is unbounded, and it rode inside every token
 * issued for that project. A 10k-character name mints a token no
 * `Authorization` header will carry, and the person who breaks it need not be
 * the person who named it: one org member names the project, every member who
 * selects it gets an unusable token.
 *
 * Dropping it cost nothing, which is the part worth recording. Those four
 * fields were WRITTEN here and read almost nowhere:
 *
 *   projectName · organizationId · accessHost   re-fetched by
 *                                               resolveProjectFromToken anyway,
 *                                               which reads them off the
 *                                               project-key cache, never off
 *                                               the payload
 *   userEmail                                   written at issue, read by
 *                                               nothing at all
 *
 * So the seal was carrying four values for the benefit of one informational
 * field in one endpoint's response body. Same reasoning as keeping the project
 * API key out: display data that can be re-fetched does not belong in a
 * credential.
 *
 * The rule for anyone adding a field: it must be platform-issued and bounded,
 * or it does not go in. A caller-influenced string in here is a denial of
 * service against everyone who shares the resource it names.
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

  /** The project chosen at sign-in. A per-call or per-URL project replaces
   *  this later; it is here now so nothing else has to change at once. */
  projectId: string;
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

/**
 * The longest token we will hand out — the belt to go with the braces above.
 *
 * The payload is bounded by construction now, so this should never fire. It
 * exists because that sentence has been wrong three times today: a client id, a
 * sealed state and this token were each "bounded" until a field turned out not
 * to be. The one remaining variable-length value in here is the platform's own
 * access token, which is not ours to bound.
 *
 * The number comes from measurements rather than from a round constant. Iris
 * drove the real chain — Cloudflare, the Fly proxy, Node's 16KB default — with
 * a synthetic bearer, and the rest is this seal measured directly:
 *
 *   15512 chars   accepted by the whole chain
 *   15573 chars   431 Request Header Fields Too Large
 *    1483 chars   what the old payload minted
 *   ~1250 chars   what this payload mints (the four dropped fields cost 233)
 *
 * So 4096 is ~3.3x the real token, and it is reached when the PLATFORM's own
 * token passes ~2950 characters — roughly 3.8x its size today. Far enough away
 * that tripping this means something changed that someone should look at, and
 * far enough below 15512 that the refusal happens here, where it is explained,
 * rather than at a proxy that will not say why.
 *
 * It THROWS rather than truncating or warning, and the failure lands at
 * sign-in: the callback's error handler turns it into the OAuth error page, so
 * a person sees "something went wrong on our side" at the moment it went wrong.
 * The alternative is worse in the way that is hard to debug — a token that
 * every proxy in the chain silently refuses to carry, surfacing later as a
 * client that cannot connect for reasons nothing logs.
 */
export const MAX_ACCESS_TOKEN_LENGTH = 4096;

/**
 * How long this token is ACTUALLY good for, in seconds.
 *
 * The PR said "24h or the platform token's expiry, whichever is sooner" and the
 * code returned a flat 24h to the client. Those disagree in the direction that
 * matters: when the platform token dies first, our token stops working while
 * the client still believes it has hours left — so it keeps retrying a
 * credential we already know is dead instead of signing in again.
 *
 * The platform token is a JWT, so its `exp` is readable. We do NOT verify it —
 * it is not ours to verify, and a forged one would only ever SHORTEN what we
 * advertise, which is the harmless direction. Anything unreadable falls back to
 * our own TTL, because a token we cannot parse is not evidence of anything.
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
