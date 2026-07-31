import { describe, it, expect } from 'vitest';
import {
  AUTH_STATE_COOKIE,
  authStateCookieName,
  cookieAttributes,
  readCookies,
  newStateHandle,
  isAcceptableClientState,
  MAX_CLIENT_STATE_LENGTH,
} from './auth-state-cookie.js';

describe('the handle fits the column that broke us', () => {
  it('is far inside 255 characters', () => {
    // The whole reason this file exists: the platform stores `state` in a
    // 255-char column, and the sealed record could not be shrunk below ~410.
    for (let i = 0; i < 50; i++) {
      const handle = newStateHandle();
      expect(handle.length).toBe(32);
      expect(handle.length).toBeLessThan(255);
      expect(handle).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it('is unpredictable', () => {
    const seen = new Set(Array.from({ length: 200 }, () => newStateHandle()));
    expect(seen.size).toBe(200);
  });
});

describe('cookie attributes', () => {
  it('is SameSite=Lax, because Strict would withhold it on the callback', () => {
    // The callback is a top-level GET navigation from the platform's origin.
    // Lax sends cookies on exactly that; Strict does not — a Strict cookie
    // would be invisible at the one moment it is needed and every sign-in
    // would fail. This assertion exists to stop a later "hardening".
    expect(cookieAttributes('https://mcp.insforge.dev').sameSite).toBe('lax');
  });

  it('is HttpOnly', () => {
    expect(cookieAttributes('https://mcp.insforge.dev').httpOnly).toBe(true);
  });

  it('follows the public URL for Secure rather than hardcoding it', () => {
    // A Secure cookie is silently dropped on plaintext http, and local runs are
    // http://127.0.0.1 — hardcoding true makes every local sign-in fail in a
    // way that looks like a code bug.
    expect(cookieAttributes('https://mcp.insforge.dev').secure).toBe(true);
    expect(cookieAttributes('http://127.0.0.1:3000').secure).toBe(false);
  });
});

describe('the cookie name a co-tenant cannot set', () => {
  it('uses __Host- wherever there is TLS', () => {
    // *.run.mcp-use.com is a shared parent domain with our own insta-mcp
    // servers as neighbours. Any co-tenant can set a Domain cookie of any name
    // for the parent; __Host- is the only mechanism that stops it, because a
    // browser refuses to store one unless it is Secure, Path=/ and has no
    // Domain — which together mean only the exact host can set it.
    expect(authStateCookieName('https://keen-pulse-fsjr9.run.mcp-use.com')).toBe(
      '__Host-mcp_oauth_state'
    );
  });

  it('falls back only when there is no TLS at all', () => {
    // __Host- requires Secure and a Secure cookie is dropped on plaintext
    // http, which is local development and nothing else.
    expect(authStateCookieName('http://127.0.0.1:3000')).toBe('mcp_oauth_state');
  });

  it('takes Path=/ , which __Host- requires and which costs nothing', () => {
    // A cookie path was never a security boundary: any path on a host can read
    // or set that host's cookies. The prefix buys a guarantee the path did not.
    expect(cookieAttributes('https://mcp.insforge.dev').path).toBe('/');
  });
});

describe('readCookies survives a hostile neighbour', () => {
  const N = AUTH_STATE_COOKIE;
  const ours = 'v1.OURS';

  it('finds the value among others', () => {
    expect(readCookies(`a=1; ${N}=v1.abc; b=2`, N)).toEqual(['v1.abc']);
  });

  it('percent-decodes, because that is how it was written', () => {
    expect(readCookies(`${N}=v1.a%2Bb%3D`, N)).toEqual(['v1.a+b=']);
  });

  it('returns EVERY match, so a shadowing cookie cannot substitute itself', () => {
    // Measured on the shipped version: taking the first match meant a
    // co-tenant's value was read INSTEAD of ours. Returning all of them makes
    // shadowing inert, because a shadowing value simply fails to decrypt and
    // the caller tries the next.
    expect(readCookies(`${N}=v1.ATTACKER; ${N}=${ours}`, N)).toEqual(['v1.ATTACKER', ours]);
    expect(readCookies(`${N}=${ours}; ${N}=v1.ATTACKER`, N)).toEqual([ours, 'v1.ATTACKER']);
  });

  it('skips a malformed value and keeps looking', () => {
    // The worse of the two: the old code RETURNED on a decode error, so one
    // bad percent-escape from a neighbour was a permanent sign-in outage
    // needing no crypto and no knowledge of our internals.
    expect(readCookies(`${N}=%E0%A4%A; ${N}=${ours}`, N)).toEqual([ours]);
    expect(readCookies(`${N}=${ours}; ${N}=%E0%A4%A`, N)).toEqual([ours]);
    expect(readCookies(`${N}=%E0%A4%A`, N)).toEqual([]);
  });

  it('does not match a name that merely contains ours', () => {
    expect(readCookies(`x_${N}=nope`, N)).toEqual([]);
    expect(readCookies(`${N}_x=nope`, N)).toEqual([]);
  });

  it('handles no header, an empty header and a valueless entry', () => {
    expect(readCookies(undefined, N)).toEqual([]);
    expect(readCookies('', N)).toEqual([]);
    expect(readCookies('justaname', N)).toEqual([]);
  });
});

describe('the client state is bounded before we seal it', () => {
  it('accepts what real clients send, and absence', () => {
    expect(isAcceptableClientState(undefined)).toBe(true);
    expect(isAcceptableClientState('')).toBe(true);
    expect(isAcceptableClientState('s'.repeat(43))).toBe(true);
    expect(isAcceptableClientState('s'.repeat(MAX_CLIENT_STATE_LENGTH))).toBe(true);
  });

  it('rejects one character over, and non-strings', () => {
    // Unbounded client state means an unbounded cookie, which is the same
    // whole-payload mistake one layer down.
    expect(isAcceptableClientState('s'.repeat(MAX_CLIENT_STATE_LENGTH + 1))).toBe(false);
    for (const bad of [42, {}, ['a'], null]) {
      expect(isAcceptableClientState(bad)).toBe(false);
    }
  });
});
