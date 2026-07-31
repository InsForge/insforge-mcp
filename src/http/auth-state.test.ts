import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import { sealAuthState, openAuthState, InvalidAuthStateError, AUTH_STATE_TTL_SECONDS } from './auth-state.js';
import { deriveAuthStateKey, deriveClientIdSigningKey } from './config.js';

const KEY = deriveAuthStateKey('a-platform-client-secret');
const OTHER = deriveAuthStateKey('a-different-client-secret');

const STATE = {
  clientId: 'mcp_abc.def',
  redirectUri: 'http://127.0.0.1:8765/callback',
  scope: 'mcp:read mcp:write',
  state: 'client-csrf-value',
  codeChallenge: 'a'.repeat(43),
  codeChallengeMethod: 'S256',
  insforgeCodeVerifier: 'v'.repeat(43),
  createdAt: 1785480000000,
};

describe('authorization state round-trips', () => {
  it('returns exactly what was sealed', () => {
    expect(openAuthState(sealAuthState(STATE, KEY), KEY)).toEqual(STATE);
  });

  it('produces a different blob every time for the same input', () => {
    // A fresh nonce per seal. A repeated nonce under one key is how GCM fails
    // catastrophically, so this is the property, not a nicety.
    const a = sealAuthState(STATE, KEY);
    const b = sealAuthState(STATE, KEY);
    expect(a).not.toBe(b);
    expect(openAuthState(a, KEY)).toEqual(openAuthState(b, KEY));
  });
});

describe('the PKCE verifier is not readable from the sealed value', () => {
  // This is the whole reason auth state is encrypted rather than signed, like
  // client ids are. The state parameter travels through the platform and sits
  // in the browser's address bar; a signed-but-readable envelope would publish
  // the verifier to exactly the party PKCE defends against.
  it('does not contain the verifier in any obvious encoding', () => {
    const sealed = sealAuthState(STATE, KEY);
    const body = sealed.slice('v1.'.length);
    const decoded = Buffer.from(body, 'base64url').toString('binary');

    for (const haystack of [sealed, decoded]) {
      expect(haystack).not.toContain(STATE.insforgeCodeVerifier);
      expect(haystack).not.toContain('insforgeCodeVerifier');
    }
    // ...nor the client's own redirect, which would make the blob a target list.
    expect(sealed).not.toContain('127.0.0.1');
  });
});

describe('a sealed state cannot be forged or altered', () => {
  it('refuses another key', () => {
    expect(() => openAuthState(sealAuthState(STATE, KEY), OTHER)).toThrow(InvalidAuthStateError);
  });

  it('refuses a key derived with the other label from the same secret', () => {
    // Same environment variable, different purpose. If these collided, a public
    // client id and a secret-bearing auth state would share a key.
    const secret = 'one-secret-two-purposes';
    const clientIdKey = Buffer.from(deriveClientIdSigningKey(secret), 'base64url');
    expect(clientIdKey.length).toBe(32);
    expect(clientIdKey.equals(deriveAuthStateKey(secret))).toBe(false);
    expect(() => openAuthState(sealAuthState(STATE, deriveAuthStateKey(secret)), clientIdKey)).toThrow(
      InvalidAuthStateError
    );
  });

  it('refuses a single flipped byte anywhere in the blob', () => {
    const sealed = sealAuthState(STATE, KEY);
    const raw = Buffer.from(sealed.slice(3), 'base64url');
    for (const i of [0, 6, 12, 20, raw.length - 1]) {
      const tampered = Buffer.from(raw);
      tampered[i] ^= 0x01;
      expect(() => openAuthState(`v1.${tampered.toString('base64url')}`, KEY)).toThrow(
        InvalidAuthStateError
      );
    }
  });

  it('refuses values that are not ours at all', () => {
    for (const bad of ['', 'v1.', 'v1.notbase64!!', 'v2.abc', 'abc', 'v1.' + 'A'.repeat(20)]) {
      expect(() => openAuthState(bad, KEY), bad).toThrow(InvalidAuthStateError);
    }
  });

  it('refuses non-strings', () => {
    for (const bad of [undefined, null, 42, {}]) {
      expect(() => openAuthState(bad as unknown as string, KEY)).toThrow(InvalidAuthStateError);
    }
  });
});

describe('expiry travels inside the seal', () => {
  const T0 = 1_700_000_000_000;

  it('accepts up to the TTL and refuses after it', () => {
    const sealed = sealAuthState(STATE, KEY, T0);
    expect(openAuthState(sealed, KEY, T0)).toEqual(STATE);
    expect(openAuthState(sealed, KEY, T0 + AUTH_STATE_TTL_SECONDS * 1000 - 1)).toEqual(STATE);
    expect(() => openAuthState(sealed, KEY, T0 + AUTH_STATE_TTL_SECONDS * 1000)).toThrow(
      InvalidAuthStateError
    );
  });

  it('cannot have its expiry extended by whoever holds the blob', () => {
    // exp is inside the ciphertext, so it is covered by the auth tag. If it sat
    // beside the blob it could simply be rewritten.
    const sealed = sealAuthState(STATE, KEY, T0);
    const raw = Buffer.from(sealed.slice(3), 'base64url');
    // Flip bytes across the ciphertext body; every attempt must be rejected
    // rather than yielding a state with a later expiry.
    for (let i = 28; i < Math.min(raw.length, 60); i += 7) {
      const tampered = Buffer.from(raw);
      tampered[i] ^= 0xff;
      expect(() => openAuthState(`v1.${tampered.toString('base64url')}`, KEY, T0)).toThrow(
        InvalidAuthStateError
      );
    }
  });
});

describe(`a wrong key is our fault, not the caller's`, () => {
  it('throws a plain Error, never InvalidAuthStateError', () => {
    // Distinct on purpose: a misconfigured server must not report itself to a
    // client as "your state is invalid", which is the mislabelling that sends
    // someone to re-add a working install.
    for (const bad of [Buffer.alloc(16), Buffer.alloc(0), 'not a buffer' as unknown as Buffer]) {
      expect(() => sealAuthState(STATE, bad)).toThrow(Error);
      expect(() => sealAuthState(STATE, bad)).not.toThrow(InvalidAuthStateError);
    }
  });
});

describe('the TTL is per-value, because a code is not a state', () => {
  const KEY2 = deriveAuthStateKey('another-secret');
  const T0 = 1_700_000_000_000;

  it('honours a shorter TTL than the default', () => {
    // RFC 6749 §4.1.2 wants an authorization code short-lived, and a code that
    // cannot be single-use (nothing to delete) wants it more. Five minutes for
    // codes, ten for state.
    const sealed = sealAuthState({ code: true }, KEY2, T0, 5 * 60);
    expect(openAuthState(sealed, KEY2, T0 + 5 * 60 * 1000 - 1)).toEqual({ code: true });
    expect(() => openAuthState(sealed, KEY2, T0 + 5 * 60 * 1000)).toThrow(InvalidAuthStateError);
  });

  it('still defaults to the state TTL when none is given', () => {
    const sealed = sealAuthState({ state: true }, KEY2, T0);
    expect(openAuthState(sealed, KEY2, T0 + AUTH_STATE_TTL_SECONDS * 1000 - 1)).toEqual({ state: true });
    expect(() => openAuthState(sealed, KEY2, T0 + AUTH_STATE_TTL_SECONDS * 1000)).toThrow();
  });
});

describe('three purposes, three keys', () => {
  it(`gives each label a key that rejects the other's output`, async () => {
    const { deriveAuthCodeKey } = await import('./config.js');
    const secret = 'one-secret-three-purposes';
    const stateKey = deriveAuthStateKey(secret);
    const codeKey = deriveAuthCodeKey(secret);

    expect(stateKey.equals(codeKey)).toBe(false);
    // An auth code must not be openable as an auth state, or a weakness in the
    // most exposed value reaches the other.
    expect(() => openAuthState(sealAuthState({ x: 1 }, codeKey), stateKey)).toThrow(
      InvalidAuthStateError
    );
    expect(() => openAuthState(sealAuthState({ x: 1 }, stateKey), codeKey)).toThrow(
      InvalidAuthStateError
    );
  });
});
