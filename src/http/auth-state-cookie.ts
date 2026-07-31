import { randomBytes } from 'crypto';

/**
 * Where the sealed authorization state actually travels.
 *
 * #87 put the whole sealed envelope in the OAuth `state` parameter. Every byte
 * budget it was measured against — Node's max-http-header-size, nginx's request
 * line — was satisfied, and the platform still returned 500: it stores `state`
 * in a **255-character column**. A limit nobody greps for, enforced by a
 * different system, one hop past where I stopped measuring.
 *
 * Shrinking does not reach 255. The floor for a state that can still complete a
 * callback is ~410 characters, measured across every variant the flow permits.
 * So the envelope has to travel somewhere else, and `state` goes back to being
 * a short handle.
 *
 * A cookie on our own origin is that somewhere, and it is not sufficient on its
 * own either — it moves the bound to roughly 4096 bytes rather than removing
 * one. Both halves are needed: drop the client id from the seal (nothing reads
 * it after authorize) and bound the client's own `state`, so every component is
 * bounded rather than hoped about.
 *
 *   client_id at its 4096 cap, client state 512   6639   OVER a 4096 cookie
 *   no client_id, client state bounded to 512     1159   fits
 *   realistic (loopback, 43-char state)            544   ample
 *
 * The handle is not decoration. It is in the `state` parameter AND inside the
 * sealed payload, and the callback requires them to match — a double-submit
 * binding. Without it the cookie alone would authorise any callback that
 * arrived with a cookie, which is the CSRF the `state` parameter exists to
 * prevent.
 */

/** The cookie carrying the sealed state. Scoped to the OAuth routes only. */
export const AUTH_STATE_COOKIE = 'mcp_oauth_state';

/**
 * How long the cookie lives. Matches the seal's own expiry — the seal is
 * authoritative, since a cookie's Max-Age is a request from us that the browser
 * is free to ignore.
 */
export const AUTH_STATE_COOKIE_MAX_AGE_SECONDS = 10 * 60;

/**
 * A handle for one authorization, short enough for a 255-char column with room
 * for anything else the platform decides to put beside it.
 */
export function newStateHandle(): string {
  return randomBytes(16).toString('hex'); // 32 chars
}

export interface CookieAttributes {
  httpOnly: true;
  secure: boolean;
  sameSite: 'lax';
  path: string;
  maxAge: number;
}

/**
 * Attributes for the state cookie.
 *
 * `sameSite: 'lax'` is load-bearing and NOT a weaker choice made for
 * convenience. The callback arrives as a top-level GET navigation from the
 * platform's origin. Lax sends cookies on exactly that; **Strict withholds
 * them**, so a Strict cookie would be invisible at the one moment it is needed
 * and every sign-in would fail with a missing state. This is the kind of
 * setting that gets "hardened" later by someone who has not traced the
 * navigation, so: do not.
 *
 * `secure` follows the public URL rather than being hardcoded, because a
 * Secure cookie is silently dropped on plaintext http and local development
 * runs on http://127.0.0.1. Hardcoding true makes every local run fail in a way
 * that looks like a code bug.
 */
export function cookieAttributes(publicUrl: string, oauthPathPrefix = '/oauth'): CookieAttributes {
  return {
    httpOnly: true,
    secure: publicUrl.startsWith('https://'),
    sameSite: 'lax',
    path: oauthPathPrefix,
    maxAge: AUTH_STATE_COOKIE_MAX_AGE_SECONDS * 1000,
  };
}

/**
 * Read one cookie out of a raw Cookie header.
 *
 * Hand-rolled rather than adding cookie-parser: this reads exactly one name,
 * and a dependency whose whole job is `split('; ')` is a dependency to keep
 * patched forever. Values are percent-encoded on the way out, so decode here.
 */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (typeof header !== 'string' || header.length === 0) return undefined;

  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const raw = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      // A malformed value is not ours; treat it as absent rather than throwing
      // a decode error out of the middle of a sign-in.
      return undefined;
    }
  }
  return undefined;
}

/**
 * The longest client-supplied `state` we will accept.
 *
 * The client's `state` rides inside our sealed envelope, so an unbounded one is
 * an unbounded cookie. 512 is far above anything a real client sends (the SDK
 * uses 32 random bytes) and keeps the worst case inside 4096 with room.
 */
export const MAX_CLIENT_STATE_LENGTH = 512;

export function isAcceptableClientState(value: unknown): boolean {
  return value === undefined || (typeof value === 'string' && value.length <= MAX_CLIENT_STATE_LENGTH);
}
