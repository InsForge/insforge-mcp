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

/**
 * The cookie carrying the sealed state.
 *
 * `__Host-` is not decoration. On a shared parent domain — which
 * `*.run.mcp-use.com` is, with our own insta-mcp servers as neighbours — any
 * co-tenant can set a Domain cookie of ANY name for the parent, and the browser
 * sends it to us alongside our own. The prefix is the only mechanism that stops
 * that: a browser refuses to store a `__Host-` cookie unless it has Secure, has
 * Path=/, and has NO Domain attribute, which together mean only the exact host
 * can set it.
 *
 * Path=/ rather than /oauth is the cost, and it is not a real one — cookie paths
 * were never a security boundary; any path on a host can read or set the host's
 * cookies. The prefix buys a guarantee, the path never did.
 *
 * The name falls back only when there is no TLS at all, because `__Host-`
 * requires Secure and a Secure cookie is dropped on plaintext http. That is
 * local development and nothing else — no deployment of this server runs
 * without https — but it is a fallback, and fallbacks are how protections get
 * lost, so it is keyed on the scheme rather than on an environment flag someone
 * could set.
 */
export function authStateCookieName(publicUrl: string): string {
  return publicUrl.startsWith('https://') ? '__Host-mcp_oauth_state' : 'mcp_oauth_state';
}

/** @deprecated Prefer authStateCookieName(publicUrl); kept for the http case. */
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
export function cookieAttributes(publicUrl: string): CookieAttributes {
  return {
    httpOnly: true,
    secure: publicUrl.startsWith('https://'),
    sameSite: 'lax',
    // Path=/ is required by __Host-, and costs nothing: a cookie path has never
    // been a security boundary. Any path on the host can read or set it.
    path: '/',
    maxAge: AUTH_STATE_COOKIE_MAX_AGE_SECONDS * 1000,
  };
}

/**
 * Read EVERY cookie with this name, not the first.
 *
 * The first version returned the first match and gave up on a decode error, and
 * both of those were exploitable by a co-tenant on a shared parent domain.
 * Measured on the shipped code rather than argued:
 *
 *   Cookie: NAME=v1.ATTACKER; NAME=<ours>   -> we read the attacker's
 *   Cookie: NAME=%E0%A4%A;    NAME=<ours>   -> we read undefined, forever
 *
 * The second is the worse one: a single malformed percent-escape from a
 * neighbour is a permanent sign-in outage needing no crypto, no timing and no
 * knowledge of our internals. "Fails closed" was the wrong frame — the question
 * is closed for WHOM, and it was closed for us and open for them.
 *
 * So: collect every candidate, skip the ones that will not decode, and let the
 * caller try each. Shadowing becomes inert because a shadowing value simply
 * fails to open and the next one is tried. This matters more than the
 * `__Host-` prefix, because it survives someone dropping the prefix later —
 * which is exactly how this class of bug comes back.
 */
export function readCookies(header: string | undefined, name: string): string[] {
  if (typeof header !== 'string' || header.length === 0) return [];

  const found: string[] = [];
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const raw = part.slice(eq + 1).trim();
    try {
      found.push(decodeURIComponent(raw));
    } catch {
      // Not ours — ours is base64url and always decodes. CONTINUE rather than
      // return: one bad neighbour must not end the search.
      continue;
    }
  }
  return found;
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
