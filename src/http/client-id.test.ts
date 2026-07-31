import { describe, it, expect } from 'vitest';
import {
  mintClientId,
  readClientId,
  isRegisteredRedirectUri,
  InvalidClientIdError,
} from './client-id.js';

const SECRET = 'test-signing-secret';
const OTHER_SECRET = 'a-different-signing-secret';
const CALLBACK = 'http://127.0.0.1:8765/callback';

describe('client ids carry their own registration', () => {
  it('round-trips what the client registered', () => {
    const id = mintClientId({ redirect_uris: [CALLBACK], client_name: 'Claude Code' }, SECRET);
    const reg = readClientId(id, SECRET);

    expect(reg.redirect_uris).toEqual([CALLBACK]);
    expect(reg.client_name).toBe('Claude Code');
    expect(typeof reg.iat).toBe('number');
  });

  it('is recognisable as ours', () => {
    expect(mintClientId({ redirect_uris: [CALLBACK] }, SECRET).startsWith('mcp_')).toBe(true);
  });

  it('does not expire', () => {
    // The stored version expired after 30 days and silently broke every client
    // installed that long. A redirect_uri does not go stale.
    const tenYearsAgo = Math.floor(Date.now() / 1000) - 10 * 365 * 24 * 60 * 60;
    const id = mintClientId({ redirect_uris: [CALLBACK] }, SECRET, tenYearsAgo);

    expect(readClientId(id, SECRET).redirect_uris).toEqual([CALLBACK]);
  });
});

describe('a client id cannot be forged', () => {
  it('rejects a payload edited to claim another redirect_uri', () => {
    // The attack this whole module exists to stop: change where the code goes.
    const id = mintClientId({ redirect_uris: [CALLBACK] }, SECRET);
    const [payload, signature] = id.slice('mcp_'.length).split('.');
    const tampered = Buffer.from(
      JSON.stringify({ redirect_uris: ['https://attacker.example/steal'], iat: 1 })
    ).toString('base64url');

    expect(() => readClientId(`mcp_${tampered}.${signature}`, SECRET)).toThrow(InvalidClientIdError);
    // and the original still verifies, so the test is about the edit, not the shape
    expect(readClientId(`mcp_${payload}.${signature}`, SECRET).redirect_uris).toEqual([CALLBACK]);
  });

  it('rejects an id signed with a different secret', () => {
    const id = mintClientId({ redirect_uris: [CALLBACK] }, OTHER_SECRET);
    expect(() => readClientId(id, SECRET)).toThrow(InvalidClientIdError);
  });

  it('rejects ids that are not ours at all', () => {
    for (const bad of ['', 'mcp_', 'mcp_nodot', 'mcp_.sig', 'mcp_payload.', 'random-string']) {
      expect(() => readClientId(bad, SECRET)).toThrow(InvalidClientIdError);
    }
  });

  it('rejects a signed payload that is not a registration', () => {
    // Signed by us, but a shape we never intended to mint.
    const payload = Buffer.from(JSON.stringify({ redirect_uris: [] })).toString('base64url');
    const id = mintClientId({ redirect_uris: [CALLBACK] }, SECRET);
    const signature = id.slice(id.lastIndexOf('.') + 1);
    expect(() => readClientId(`mcp_${payload}.${signature}`, SECRET)).toThrow(InvalidClientIdError);
  });

  it('refuses to work without a secret', () => {
    expect(() => mintClientId({ redirect_uris: [CALLBACK] }, '')).toThrow();
    expect(() => readClientId('mcp_a.b', '')).toThrow();
  });
});

describe('redirect_uri matching', () => {
  const reg = readClientId(
    mintClientId({ redirect_uris: [CALLBACK, 'https://app.example/cb'] }, SECRET),
    SECRET
  );

  it('accepts a registered uri exactly', () => {
    expect(isRegisteredRedirectUri(reg, CALLBACK)).toBe(true);
    expect(isRegisteredRedirectUri(reg, 'https://app.example/cb')).toBe(true);
  });

  it('rejects prefix and origin near-misses', () => {
    // These are the relaxations that turn a redirect_uri check into an open
    // redirect, which on an authorize endpoint is code theft.
    for (const near of [
      'http://127.0.0.1:8765/callback/../evil',
      'http://127.0.0.1:8765/callback2',
      'http://127.0.0.1:8765',
      'https://app.example/cb?next=https://attacker.example',
      'https://app.example.attacker.test/cb',
      'HTTP://127.0.0.1:8765/callback',
    ]) {
      expect(isRegisteredRedirectUri(reg, near)).toBe(false);
    }
  });

  it('rejects non-strings', () => {
    for (const bad of [undefined, null, 42, ['a'], {}]) {
      expect(isRegisteredRedirectUri(reg, bad)).toBe(false);
    }
  });
});

describe('a missing secret is never silently substituted', () => {
  it('refuses to mint or read without one', () => {
    // Quinn's catch: a per-boot generated fallback would invalidate every
    // client id on every restart, handing every user the re-add page at once
    // — a mass logout dressed up as a convenience. There is deliberately no
    // way to get a working signer without supplying the secret, so wiring
    // cannot reach for one by accident.
    for (const missing of ['', undefined as unknown as string, null as unknown as string]) {
      expect(() => mintClientId({ redirect_uris: [CALLBACK] }, missing)).toThrow();
      expect(() => readClientId('mcp_a.b', missing)).toThrow();
    }
  });

  it('exports no secret generator', async () => {
    const mod = await import('./client-id.js');
    expect(Object.keys(mod)).not.toContain('generateSigningSecret');
  });
});
