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
 * And a bound on the id itself, which is the only one of these that is actually
 * about the URL.
 *
 * The per-field bounds above never constrained their product: 10 x 2048 plus a
 * 256-character name is a legal registration under every one of them, and it
 * mints a 27807-character client id. Measured, not reasoned about — that
 * registration returns 201 and the authorize request it produces is 29944
 * characters and comes back 431 Request Header Fields Too Large. Node's default
 * max-http-header-size is 16384 and the request line counts toward it; nginx in
 * front cuts the request line at 8192. So the comment above described this
 * exact failure and the constants permitted it.
 *
 * 4096 is chosen from the same arithmetic rather than by feel: the worst
 * authorize request line is this id plus an encoded redirect_uri plus about 150
 * characters of other parameters, so 4096 stays inside the 8192 that fails
 * first, with room. A realistic registration mints 198.
 *
 * Checked at mint only, deliberately. `readClientId` does not re-check it, so
 * tightening this number later cannot invalidate ids already issued — the
 * failure mode that made the 30-day TTL so expensive.
 */
const MAX_CLIENT_ID_LENGTH = 4096;

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
 *
 * The membership is set by measurement, not by taste. A reviewer proposed a
 * structural rule instead — reject anything whose scheme is not http(s) and
 * does not look like a private-use scheme. Running that rule against the six
 * examples it was offered for closed three of them and left `intent://`,
 * `chrome://` and `about:blank` accepted, while reading as though it had closed
 * all six. Probing the same six against the platform whose filter we match 12
 * for 12 found it accepts five of them. Adopting the structural rule would have
 * made us stricter than the thing we chose to copy, for the same reason we did
 * not copy an allowlist: principled rules reject `cursor://`.
 *
 * `about:` is the one value where we genuinely diverged, so it is here.
 *
 * Exported so a test can assert the property over every member rather than
 * over a hand-copied list — a test named for a class that checks five
 * instances stops covering the sixth the moment one is added.
 */
export const FORBIDDEN_SCHEMES: ReadonlySet<string> = new Set([
  'javascript:',
  'data:',
  'vbscript:',
  'file:',
  'blob:',
  'about:',
]);

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
  const clientId = `${PREFIX}${payload}.${sign(payload, secret)}`;

  // Measure the thing that actually travels. One check on the finished id
  // cannot drift out of sync with the per-field bounds the way a fourth
  // per-field bound would, and it is the only one whose units match the limit
  // that fails — bytes on a request line.
  if (clientId.length > MAX_CLIENT_ID_LENGTH) {
    throw new InvalidRegistrationError(
      `this registration mints a ${clientId.length}-character client_id, over the ` +
        `${MAX_CLIENT_ID_LENGTH} limit. The client_id travels in every authorize URL, ` +
        'so an oversized one is rejected by the server or a proxy before it is read. ' +
        'Register fewer or shorter redirect_uris.'
    );
  }

  return clientId;
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
 * A loopback IP literal, per RFC 8252 §7.3.
 *
 * `localhost` is deliberately excluded. §8.3 says a native client should use
 * the IP literal precisely because `localhost` resolves through DNS and the
 * hosts file, so it can be pointed somewhere that is not the loopback
 * interface. The platform's `matchRedirectUri` draws the line in the same
 * place, and the two servers agreeing is worth more here than the extra
 * leniency would be.
 */
function isLoopbackIpLiteral(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
}

/**
 * Is this redirect_uri one the client registered?
 *
 * Exact string match, per RFC 6749 §3.1.2.3 — with the one relaxation RFC 8252
 * §7.3 requires and no others. No prefix matching and no origin matching: those
 * are what turn a redirect_uri check into an open redirect, and an open
 * redirect on an authorization endpoint is authorization-code theft.
 *
 * The exception is loopback. A native client binds an ephemeral port, so the
 * port it registers is not the port it will be listening on next time, and an
 * exact match rejects it. Concretely: register on 127.0.0.1:54321, restart,
 * bind 61999, and the MCP SDK sends the cached client_id with the new port —
 * it re-registers only when it holds no client information at all
 * (`client/auth.js:226`), and never in response to an authorize-time rejection.
 * So the user gets the re-add page on every restart, with nothing they can do
 * about it.
 *
 * For loopback IP literals the port is ignored and scheme, hostname, path and
 * query must all still match exactly. Everything else keeps exact match,
 * including the port. This mirrors the platform's `matchRedirectUri`
 * (`src/utils/oauth.ts:386`) rather than inventing a second dialect —
 * flattening that function to `includes()` is what would have broken
 * `insforge login`, whose CLI binds `server.listen(0, '127.0.0.1')`.
 */
export function isRegisteredRedirectUri(
  registration: ClientRegistration,
  redirectUri: unknown
): boolean {
  if (typeof redirectUri !== 'string') return false;
  if (registration.redirect_uris.includes(redirectUri)) return true;

  let requested: URL;
  try {
    requested = new URL(redirectUri);
  } catch {
    return false;
  }
  if (!isLoopbackIpLiteral(requested.hostname)) return false;

  return registration.redirect_uris.some((registered) => {
    let candidate: URL;
    try {
      candidate = new URL(registered);
    } catch {
      return false;
    }
    return (
      isLoopbackIpLiteral(candidate.hostname) &&
      candidate.protocol === requested.protocol &&
      candidate.hostname === requested.hostname &&
      candidate.pathname === requested.pathname &&
      candidate.search === requested.search
    );
  });
}
