import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Client registrations as signed values rather than stored rows.
 *
 * `/oauth/register` currently writes a Redis row and hands back a random id;
 * `/oauth/authorize` reads that row back to learn the client's redirect_uris.
 * That row is one of the five things keeping Redis on the critical path, and
 * it is pure derived data — the only thing we learn from it is what the client
 * already told us at registration.
 *
 * So carry it in the id. The id is `<payload>.<signature>`: the payload is the
 * registration, the signature is ours. Anyone can read a client id (it travels
 * in every authorize URL and is not a secret), but only we can mint one, which
 * is the property that matters — an attacker cannot invent a client id that
 * claims a redirect_uri we never approved.
 *
 * This is the mcp-use `oauthProxy` shape with the check that implementation
 * omits: it never validates redirect_uri against the registration, which is
 * what makes authorization-code theft possible there. Here the registration
 * IS the id, so the check cannot be skipped by accident — there is nothing
 * else to compare against.
 */

/** What a client told us about itself at registration. */
export interface ClientRegistration {
  redirect_uris: string[];
  client_name?: string;
  /** Seconds since epoch, for diagnostics. Not used for expiry — see below. */
  iat: number;
}

export class InvalidClientIdError extends Error {}

/**
 * A registration we refuse to mint. Separate from InvalidClientIdError because
 * the two mean different things to a caller: this one is the client's fault at
 * registration time (RFC 7591 `invalid_client_metadata`, 400), the other is an
 * id that does not verify at authorize time.
 */
export class InvalidRegistrationError extends Error {}

const PREFIX = 'mcp_';

/**
 * Bounds on what a registration may contain.
 *
 * The payload IS the client id, and the client id travels in every authorize
 * URL, so an unbounded registration is an unbounded URL. Browsers and proxies
 * cut those off well before Node does, and the failure would land on the
 * authorize redirect rather than on registration where it could be explained.
 * These are far above what any real client sends.
 */
const MAX_REDIRECT_URIS = 10;
const MAX_URI_LENGTH = 2048;
const MAX_CLIENT_NAME_LENGTH = 256;

/**
 * Schemes we will not carry in a registration.
 *
 * The authorize endpoint redirects to whatever the registration names, so this
 * is the one place to keep script-capable and opaque schemes out. Browsers
 * already refuse to navigate to `javascript:` or `data:` in a Location header,
 * so this is defence in depth rather than the only guard.
 *
 * Deliberately a denylist and not an allowlist. RFC 8252 §7.1 says a native
 * client should use a reversed-domain private-use scheme (`com.example.app:`),
 * and real MCP clients simply do not — `cursor://`, `vscode://` and friends are
 * what actually arrives. An allowlist of https + loopback http + dotted schemes
 * is the more principled rule and it would reject working clients today, which
 * is the failure this whole module exists to stop happening silently.
 */
const FORBIDDEN_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'file:', 'blob:']);

/**
 * Is this a redirect_uri we are willing to sign?
 *
 * Absolute (a relative URI would resolve against our own origin), not
 * script-capable, and plaintext http only for loopback — per RFC 8252 §8.3 a
 * native client redirects to 127.0.0.1, but anything else on http would carry
 * an authorization code in the clear.
 */
export function isAcceptableRedirectUri(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URI_LENGTH) {
    return false;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false; // not absolute, or not parseable at all
  }

  if (FORBIDDEN_SCHEMES.has(url.protocol)) {
    return false;
  }

  if (url.protocol === 'http:') {
    return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  }

  return true;
}

/**
 * Reject a registration we could sign but should not.
 *
 * `readClientId` already refuses a structurally wrong payload, so without this
 * `mintClientId` would happily issue an id that can never be read back — the
 * error surfacing at authorize time, in a browser, rather than at registration
 * where the client is listening and the message can say what to fix.
 */
function assertMintable(registration: Omit<ClientRegistration, 'iat'>): void {
  const { redirect_uris: uris, client_name: name } = registration;

  if (!Array.isArray(uris) || uris.length === 0) {
    throw new InvalidRegistrationError('redirect_uris is required and must be a non-empty array');
  }
  if (uris.length > MAX_REDIRECT_URIS) {
    throw new InvalidRegistrationError(`redirect_uris must contain at most ${MAX_REDIRECT_URIS} entries`);
  }
  for (const uri of uris) {
    if (!isAcceptableRedirectUri(uri)) {
      throw new InvalidRegistrationError(
        'each redirect_uri must be an absolute http(s) or application URI; ' +
          'plaintext http is accepted only for loopback'
      );
    }
  }
  if (name !== undefined && (typeof name !== 'string' || name.length > MAX_CLIENT_NAME_LENGTH)) {
    throw new InvalidRegistrationError(
      `client_name must be a string of at most ${MAX_CLIENT_NAME_LENGTH} characters`
    );
  }
}

function sign(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

/**
 * Mint a client id that carries its own registration.
 *
 * Deliberately not time-limited. The stored version expired after 30 days and
 * silently broke every client that had been installed that long — a bug we
 * shipped and had to fix twice. A registration describes a redirect_uri, and a
 * redirect_uri does not go stale; if we ever need to invalidate one, rotating
 * the signing secret does it for all of them at once.
 */
export function mintClientId(
  registration: Omit<ClientRegistration, 'iat'>,
  secret: string,
  now: number = Math.floor(Date.now() / 1000)
): string {
  if (!secret) {
    throw new Error('a signing secret is required to mint client ids');
  }
  assertMintable(registration);
  // Fields listed rather than spread. `registration` comes from a request body
  // once this is wired, and a spread would carry every extra key the caller
  // sent into the payload — which is the client id, which is the URL.
  const full: ClientRegistration = {
    redirect_uris: registration.redirect_uris,
    ...(registration.client_name !== undefined ? { client_name: registration.client_name } : {}),
    iat: now,
  };
  const payload = Buffer.from(JSON.stringify(full)).toString('base64url');
  return `${PREFIX}${payload}.${sign(payload, secret)}`;
}

/**
 * Recover a registration from a client id, or throw.
 *
 * Throws rather than returning null so a caller cannot accidentally treat an
 * unverified registration as valid by forgetting a null check — the failure
 * mode this whole module exists to prevent.
 */
export function readClientId(clientId: string, secret: string): ClientRegistration {
  if (!secret) {
    throw new Error('a signing secret is required to read client ids');
  }
  if (typeof clientId !== 'string' || !clientId.startsWith(PREFIX)) {
    throw new InvalidClientIdError('not a client id issued by this server');
  }

  const body = clientId.slice(PREFIX.length);
  const dot = body.lastIndexOf('.');
  if (dot <= 0 || dot === body.length - 1) {
    throw new InvalidClientIdError('malformed client id');
  }

  const payload = body.slice(0, dot);
  const provided = Buffer.from(body.slice(dot + 1));
  const expected = Buffer.from(sign(payload, secret));

  // Length-check first: timingSafeEqual throws on a length mismatch, and that
  // throw would itself be a (crude) oracle.
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new InvalidClientIdError('client id signature does not verify');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    throw new InvalidClientIdError('client id payload is not JSON');
  }

  const reg = parsed as ClientRegistration;
  if (
    !reg ||
    !Array.isArray(reg.redirect_uris) ||
    reg.redirect_uris.length === 0 ||
    !reg.redirect_uris.every((u) => typeof u === 'string' && u.length > 0)
  ) {
    // Signed by us but structurally wrong — treat as invalid rather than
    // trusting a shape we did not intend to mint.
    throw new InvalidClientIdError('client id payload is not a registration');
  }

  return reg;
}

/**
 * Is this redirect_uri one the client registered?
 *
 * Exact string match, per RFC 6749 §3.1.2.3. No prefix or origin matching:
 * those are the relaxations that turn a redirect_uri check into an open
 * redirect, and an open redirect on an authorization endpoint is
 * authorization-code theft.
 */
export function isRegisteredRedirectUri(
  registration: ClientRegistration,
  redirectUri: unknown
): boolean {
  return typeof redirectUri === 'string' && registration.redirect_uris.includes(redirectUri);
}
