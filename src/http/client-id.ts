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

const PREFIX = 'mcp_';

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
  const full: ClientRegistration = { ...registration, iat: now };
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
