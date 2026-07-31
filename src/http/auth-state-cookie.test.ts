import { describe, it, expect } from 'vitest';
import {
  AUTH_STATE_COOKIE,
  cookieAttributes,
  readCookie,
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

  it('is HttpOnly and scoped to the OAuth routes', () => {
    const attrs = cookieAttributes('https://mcp.insforge.dev');
    expect(attrs.httpOnly).toBe(true);
    expect(attrs.path).toBe('/oauth');
  });

  it('follows the public URL for Secure rather than hardcoding it', () => {
    // A Secure cookie is silently dropped on plaintext http, and local runs are
    // http://127.0.0.1 — hardcoding true makes every local sign-in fail in a
    // way that looks like a code bug.
    expect(cookieAttributes('https://mcp.insforge.dev').secure).toBe(true);
    expect(cookieAttributes('http://127.0.0.1:3000').secure).toBe(false);
  });
});

describe('readCookie', () => {
  it('finds the value among others', () => {
    expect(readCookie(`a=1; ${AUTH_STATE_COOKIE}=v1.abc; b=2`, AUTH_STATE_COOKIE)).toBe('v1.abc');
  });

  it('percent-decodes, because that is how it was written', () => {
    expect(readCookie(`${AUTH_STATE_COOKIE}=v1.a%2Bb%3D`, AUTH_STATE_COOKIE)).toBe('v1.a+b=');
  });

  it('does not match a name that merely contains ours', () => {
    expect(readCookie(`x_${AUTH_STATE_COOKIE}=nope`, AUTH_STATE_COOKIE)).toBeUndefined();
    expect(readCookie(`${AUTH_STATE_COOKIE}_x=nope`, AUTH_STATE_COOKIE)).toBeUndefined();
  });

  it('treats a malformed value as absent rather than throwing mid-sign-in', () => {
    expect(readCookie(`${AUTH_STATE_COOKIE}=%E0%A4%A`, AUTH_STATE_COOKIE)).toBeUndefined();
  });

  it('handles no header, an empty header and a valueless entry', () => {
    expect(readCookie(undefined, AUTH_STATE_COOKIE)).toBeUndefined();
    expect(readCookie('', AUTH_STATE_COOKIE)).toBeUndefined();
    expect(readCookie('justaname', AUTH_STATE_COOKIE)).toBeUndefined();
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
