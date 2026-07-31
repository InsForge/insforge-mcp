import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import {
  mintClientId,
  readClientId,
  isRegisteredRedirectUri,
  isAcceptableRedirectUri,
  InvalidClientIdError,
  InvalidRegistrationError,
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
    ]) {
      expect(isRegisteredRedirectUri(reg, near)).toBe(false);
    }
  });

  it('treats the scheme as case-insensitive, because it is', () => {
    // This used to be asserted as a near-miss and rejected, which was an
    // artifact of comparing strings rather than URLs. RFC 3986 §3.1 makes the
    // scheme case-insensitive, the destination is byte-identical, and the
    // platform's matchRedirectUri normalises the same way. Changed deliberately
    // when loopback matching started parsing instead of comparing text.
    expect(isRegisteredRedirectUri(reg, 'HTTP://127.0.0.1:8765/callback')).toBe(true);
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

describe('minting refuses what reading would reject', () => {
  // john-bot's review of the unwired module: mintClientId validated nothing
  // while readClientId enforced a shape, so mint could issue an id that could
  // never be read back. Harmless while nothing called mint; the moment
  // /oauth/register passes req.body straight in, it stops being harmless.
  it('rejects an empty or absent redirect_uris', () => {
    for (const bad of [[], undefined, null, 'https://app.example/cb', {}]) {
      expect(() =>
        mintClientId({ redirect_uris: bad as unknown as string[] }, SECRET)
      ).toThrow(InvalidRegistrationError);
    }
  });

  it('caps how many redirect_uris a registration may carry', () => {
    // The payload is the client id and the client id is in every authorize
    // URL, so an unbounded registration is an unbounded URL — and the failure
    // would land on the redirect, not here where it can be explained.
    const many = Array.from({ length: 11 }, (_, i) => `https://app.example/cb${i}`);
    expect(() => mintClientId({ redirect_uris: many }, SECRET)).toThrow(InvalidRegistrationError);
    expect(() => mintClientId({ redirect_uris: many.slice(0, 10) }, SECRET)).not.toThrow();
  });

  it('caps client_name', () => {
    expect(() =>
      mintClientId({ redirect_uris: [CALLBACK], client_name: 'x'.repeat(257) }, SECRET)
    ).toThrow(InvalidRegistrationError);
  });

  it('carries only the fields we mean to sign', () => {
    // req.body reaches this function. A spread would put every extra key the
    // caller sent into the id.
    const id = mintClientId(
      {
        redirect_uris: [CALLBACK],
        client_name: 'Claude Code',
        junk: 'x'.repeat(4096),
      } as unknown as { redirect_uris: string[]; client_name: string },
      SECRET
    );
    expect(readClientId(id, SECRET)).toEqual({
      redirect_uris: [CALLBACK],
      client_name: 'Claude Code',
      iat: expect.any(Number),
    });
    expect(id).not.toContain('junk');
  });

  it('round-trips a registration with no client_name', () => {
    const id = mintClientId({ redirect_uris: [CALLBACK] }, SECRET);
    const reg = readClientId(id, SECRET);
    expect(reg.client_name).toBeUndefined();
    expect(reg.redirect_uris).toEqual([CALLBACK]);
  });
});

describe('isAcceptableRedirectUri', () => {
  // /oauth/authorize redirects to whatever the registration names, so the mint
  // boundary is the place to keep dangerous values out entirely.
  it('accepts https anywhere', () => {
    expect(isAcceptableRedirectUri('https://app.example/cb')).toBe(true);
  });

  it('accepts plaintext http only on loopback', () => {
    expect(isAcceptableRedirectUri('http://127.0.0.1:8765/callback')).toBe(true);
    expect(isAcceptableRedirectUri('http://localhost:8765/callback')).toBe(true);
    // An authorization code over plaintext http to a remote host is the code
    // read off the wire.
    expect(isAcceptableRedirectUri('http://app.example/cb')).toBe(false);
    expect(isAcceptableRedirectUri('http://127.0.0.1.attacker.test/cb')).toBe(false);
  });

  it('accepts the private-use schemes real clients actually send', () => {
    // RFC 8252 §7.1 asks for a reversed-domain scheme; shipped MCP clients do
    // not comply, and an allowlist would reject them. Rejecting a working
    // client to enforce a SHOULD is the wrong trade here.
    for (const uri of [
      'cursor://anysphere.cursor-retrieval/oauth/callback',
      'vscode://insforge.mcp/callback',
      'com.example.app:/oauth2redirect',
    ]) {
      expect(isAcceptableRedirectUri(uri)).toBe(true);
    }
  });

  it('rejects script-capable and opaque schemes', () => {
    for (const uri of [
      'javascript:alert(1)',
      'JavaScript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'file:///etc/passwd',
      'blob:https://app.example/uuid',
    ]) {
      expect(isAcceptableRedirectUri(uri)).toBe(false);
    }
  });

  it('rejects relative and unparseable values', () => {
    // A relative URI would resolve against our own origin at redirect time.
    for (const uri of ['/callback', 'callback', '', '://nope', 'https://' + 'a'.repeat(3000)]) {
      expect(isAcceptableRedirectUri(uri)).toBe(false);
    }
  });

  it('rejects non-strings', () => {
    for (const bad of [undefined, null, 42, ['https://app.example/cb'], {}]) {
      expect(isAcceptableRedirectUri(bad)).toBe(false);
    }
  });
});

describe('the id itself is bounded, not just its parts', () => {
  // Max's P1 on the wiring PR: every field was bounded and their product was
  // not. 10 x 2048 plus a 256-char name is legal under all three per-field
  // bounds and mints a 27807-character id — which registers 201 and then comes
  // back 431 from authorize. The comment above the constants described that
  // exact failure while the constants permitted it.
  const maxUris = Array.from(
    { length: 10 },
    (_, i) => `https://app.example/${i}${'c'.repeat(2027)}`
  );

  it('rejects a registration whose per-field bounds all pass', () => {
    for (const uri of maxUris) {
      expect(isAcceptableRedirectUri(uri)).toBe(true); // each field is legal
    }
    expect(() =>
      mintClientId({ redirect_uris: maxUris, client_name: 'x'.repeat(256) }, SECRET)
    ).toThrow(InvalidRegistrationError);
  });

  it('says how big it was, so the client can act on it', () => {
    expect(() => mintClientId({ redirect_uris: maxUris }, SECRET)).toThrow(/27\d{3}-character/);
  });

  it('still mints what real clients send', () => {
    // Realistic is 198 characters; a generous four-URI registration is 1586.
    const realistic = mintClientId(
      { redirect_uris: ['cursor://anysphere.cursor-retrieval/oauth/callback'], client_name: 'Cursor' },
      SECRET
    );
    expect(realistic.length).toBeLessThan(500);

    const generous = mintClientId(
      {
        redirect_uris: Array.from({ length: 4 }, (_, i) => `https://app.example/${i}${'c'.repeat(235)}`),
        client_name: 'x'.repeat(64),
      },
      SECRET
    );
    expect(generous.length).toBeLessThan(4096);
  });

  it('does not enforce the bound on read, so tightening it later is safe', () => {
    // readClientId must never re-check this. If it did, lowering the limit
    // would invalidate every id already issued at the old one — the failure
    // mode that made the 30-day registration TTL so expensive.
    const oversized = 'a'.repeat(5000);
    const id = mintClientId({ redirect_uris: ['https://app.example/cb'] }, SECRET);
    expect(id.length).toBeLessThan(4096);
    expect(oversized.length).toBeGreaterThan(4096);

    // Hand-build an id longer than the mint bound and prove it still reads.
    const payload = Buffer.from(
      JSON.stringify({ redirect_uris: [`https://app.example/${'c'.repeat(4000)}`], iat: 1 })
    ).toString('base64url');
    const sig = createHmac('sha256', SECRET).update(payload).digest('base64url');
    const longId = `mcp_${payload}.${sig}`;
    expect(longId.length).toBeGreaterThan(4096);
    expect(readClientId(longId, SECRET).redirect_uris).toHaveLength(1);
  });
});

describe('loopback redirect_uris ignore the port (RFC 8252 §7.3)', () => {
  // Max found the same bug in the platform's matchRedirectUri, where it had
  // been flattened to includes() and would have broken `insforge login` — the
  // CLI binds server.listen(0, '127.0.0.1'), so its port differs every run.
  // The MCP had it too: a native MCP client registers on an ephemeral port,
  // and the SDK re-registers only when it holds no client information at all,
  // never in response to an authorize-time rejection. So an exact match hands
  // the user the re-add page on every restart with nothing they can do.
  const reg = (uri: string) => readClientId(mintClientId({ redirect_uris: [uri] }, SECRET), SECRET);

  it('accepts a different port on the same loopback callback', () => {
    const r = reg('http://127.0.0.1:54321/callback');
    expect(isRegisteredRedirectUri(r, 'http://127.0.0.1:54321/callback')).toBe(true);
    expect(isRegisteredRedirectUri(r, 'http://127.0.0.1:61999/callback')).toBe(true);
    expect(isRegisteredRedirectUri(r, 'http://127.0.0.1/callback')).toBe(true);
  });

  it('still requires everything except the port to match', () => {
    const r = reg('http://127.0.0.1:54321/callback');
    for (const near of [
      'http://127.0.0.1:61999/evil',            // different path
      'http://127.0.0.1:61999/callback/../x',   // path traversal
      'http://127.0.0.1:61999/callback?next=1', // query appears
      'https://127.0.0.1:61999/callback',       // different scheme
      'http://[::1]:61999/callback',            // different loopback family
    ]) {
      expect(isRegisteredRedirectUri(r, near)).toBe(false);
    }
  });

  it('does not extend the relaxation to localhost', () => {
    // RFC 8252 §8.3: localhost resolves through DNS and the hosts file, so it
    // can be pointed off the loopback interface. The platform draws the line
    // in the same place.
    const named = reg('http://localhost:54321/callback');
    expect(isRegisteredRedirectUri(named, 'http://localhost:54321/callback')).toBe(true);
    expect(isRegisteredRedirectUri(named, 'http://localhost:61999/callback')).toBe(false);

    const literal = reg('http://127.0.0.1:54321/callback');
    expect(isRegisteredRedirectUri(literal, 'http://localhost:54321/callback')).toBe(false);
  });

  it('does not extend the relaxation to anything routable', () => {
    const r = reg('https://app.example:8443/cb');
    expect(isRegisteredRedirectUri(r, 'https://app.example:8443/cb')).toBe(true);
    // A port-flexible match on a public host would let anyone with a service
    // on another port of that host collect the code.
    expect(isRegisteredRedirectUri(r, 'https://app.example:9999/cb')).toBe(false);
    expect(isRegisteredRedirectUri(r, 'https://app.example/cb')).toBe(false);
  });

  it('preserves exact match for the custom schemes clients send', () => {
    const r = reg('cursor://anysphere.cursor-retrieval/oauth/callback');
    expect(isRegisteredRedirectUri(r, 'cursor://anysphere.cursor-retrieval/oauth/callback')).toBe(true);
    expect(isRegisteredRedirectUri(r, 'cursor://anysphere.cursor-retrieval/oauth/evil')).toBe(false);
  });

  it('matches the platform on the same inputs', () => {
    // Two servers, one dialect. Divergence here is a client that works against
    // one and not the other, which is the hardest kind of bug to see.
    const r = reg('http://127.0.0.1:8765/callback');
    const platformSays: Array<[string, boolean]> = [
      ['http://127.0.0.1:8765/callback', true],
      ['http://127.0.0.1:1/callback', true],
      ['http://127.0.0.1:8765/other', false],
      ['http://localhost:8765/callback', false],
      ['https://127.0.0.1:8765/callback', false],
    ];
    for (const [uri, expected] of platformSays) {
      expect(isRegisteredRedirectUri(r, uri), uri).toBe(expected);
    }
  });
});
