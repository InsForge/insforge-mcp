import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

/**
 * Authorization state as a sealed value rather than a Redis row.
 *
 * `/oauth/authorize` writes a row keyed by a random id and hands that id to the
 * platform as the `state` parameter; `/oauth/callback` reads the row back. That
 * row is the next thing keeping Redis on the critical path, and like the client
 * registration it is pure derived data — everything in it was known at the
 * moment it was written.
 *
 * So carry it in the state parameter. The difference from client-id.ts is the
 * one that decides the mechanism:
 *
 *   a client id is PUBLIC        -> signing is enough
 *   auth state holds a SECRET    -> it has to be encrypted
 *
 * The secret is `insforgeCodeVerifier`, our PKCE verifier for the call to the
 * platform. A signed-but-readable envelope would print it in the authorize URL,
 * in the browser's address bar and in the platform's logs. PKCE exists to
 * protect against exactly the party who can read that URL, so publishing the
 * verifier there would remove the protection while leaving the ceremony.
 *
 * AES-256-GCM: confidentiality and integrity from one primitive, so there is no
 * encrypt-then-MAC ordering to get wrong. The nonce is random per seal and
 * carried alongside; a repeated nonce under one key is the way GCM fails
 * catastrophically, and 96 random bits per authorization is far below any
 * birthday concern for a value that lives ten minutes.
 *
 * SIZE, because this is the same trap one hop further along. The sealed state
 * contains the client id, and the sealed state then travels in the PLATFORM's
 * authorize URL — so a big registration inflates a request line we do not own.
 * Measured against a running server rather than estimated:
 *
 *   realistic registration   client_id  171   platform authorize URL  1037
 *   largest #82 accepts      client_id 3980   platform authorize URL  6494
 *
 * So MAX_CLIENT_ID_LENGTH (4096, chosen from the 8192 request-line limit) turns
 * out to bound this hop too, with room. That is luck rather than design:
 * anyone raising that constant has to re-measure THIS number, not only the one
 * it was chosen for.
 *
 * AND THE LIMIT THAT ACTUALLY BIT, which none of the above caught: the platform
 * stores `state` in a 255-character column. Every request-line limit is
 * satisfied and the platform still returns 500, because the constraint was a
 * database column and not a byte budget. Our 302 is real; the hop after it is
 * not, and measuring only our own response is what hid that.
 *
 * Shrinking this envelope does not fix it. Measured across every variant the
 * flow permits:
 *
 *   as built (realistic client_id)     709   over
 *   drop client_id entirely            467   over
 *   drop client_id AND client state    410   over   <- the floor for a state
 *                                                      that can still complete
 *                                                      a callback
 *   only the PKCE verifier             153   fits, but loses redirectUri, the
 *                                                   client's state and the
 *                                                   code challenge
 *
 * So `state` has to go back to being a short handle with the payload carried
 * somewhere else — a cookie on our own origin is the option that keeps this
 * module and drops nothing. Do not spend an afternoon trimming fields; 410 is
 * the floor and the column is 255.
 */

export class InvalidAuthStateError extends Error {}

/** How long a sealed state is accepted. Matches the Redis TTL it replaces. */
export const AUTH_STATE_TTL_SECONDS = 10 * 60;

const VERSION = 'v1';
const NONCE_BYTES = 12; // 96 bits, the GCM standard
const TAG_BYTES = 16;

/**
 * Seal a value so only this server can read it back.
 *
 * `expiresAt` travels INSIDE the sealed payload rather than beside it, so it is
 * covered by the authentication tag and cannot be extended by an attacker who
 * holds the blob.
 */
export function sealAuthState<T>(value: T, key: Buffer, nowMs: number = Date.now()): string {
  assertKey(key);

  const payload = JSON.stringify({
    v: value,
    exp: nowMs + AUTH_STATE_TTL_SECONDS * 1000,
  });

  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${VERSION}.${Buffer.concat([nonce, tag, body]).toString('base64url')}`;
}

/**
 * Open a sealed value, or throw.
 *
 * Throws rather than returning null for the same reason `readClientId` does: a
 * caller cannot accidentally treat an unverified value as valid by forgetting a
 * null check. Every failure — wrong key, tampered bytes, expired, malformed —
 * raises the same error type, so nothing downstream can branch on which.
 */
export function openAuthState<T>(sealed: string, key: Buffer, nowMs: number = Date.now()): T {
  assertKey(key);

  if (typeof sealed !== 'string' || !sealed.startsWith(`${VERSION}.`)) {
    throw new InvalidAuthStateError('not an authorization state issued by this server');
  }

  const raw = Buffer.from(sealed.slice(VERSION.length + 1), 'base64url');
  if (raw.length <= NONCE_BYTES + TAG_BYTES) {
    throw new InvalidAuthStateError('malformed authorization state');
  }

  const nonce = raw.subarray(0, NONCE_BYTES);
  const tag = raw.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
  const body = raw.subarray(NONCE_BYTES + TAG_BYTES);

  let plaintext: string;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch {
    // GCM's final() is what rejects a tampered or wrongly-keyed blob.
    throw new InvalidAuthStateError('authorization state does not verify');
  }

  let parsed: { v: T; exp: number };
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw new InvalidAuthStateError('authorization state payload is not JSON');
  }

  if (typeof parsed?.exp !== 'number' || !Number.isFinite(parsed.exp)) {
    throw new InvalidAuthStateError('authorization state has no expiry');
  }
  if (nowMs >= parsed.exp) {
    // Deliberately distinct wording in the message but the SAME error type, so
    // the difference is visible in a log and invisible to a caller branching on
    // the type. A sign-in that took too long is the common case here, not an
    // attack.
    throw new InvalidAuthStateError('authorization state has expired');
  }

  return parsed.v;
}

function assertKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    // Not an InvalidAuthStateError: a wrong key is our misconfiguration, and it
    // must not be reported to a caller as a bad state.
    throw new Error('a 32-byte key is required to seal or open authorization state');
  }
}
