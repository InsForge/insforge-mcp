import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';
import {
  buildResourceChallenge,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  sendUnauthorized,
} from './auth-challenge.js';

const BASE = 'https://mcp.insforge.dev';

function mockResponse() {
  const res = {
    setHeader: vi.fn(),
    status: vi.fn(() => res),
    json: vi.fn(() => res),
  };
  return res as unknown as Response & typeof res;
}

describe('protectedResourceMetadataUrl', () => {
  it('inserts the well-known path between host and resource path (RFC 9728 §3.1)', () => {
    expect(protectedResourceMetadataUrl('/mcp', BASE)).toBe(
      `${BASE}/.well-known/oauth-protected-resource/mcp`
    );
  });

  it('describes the origin at the bare well-known path', () => {
    expect(protectedResourceMetadataUrl('', BASE)).toBe(
      `${BASE}/.well-known/oauth-protected-resource`
    );
  });
});

describe('protectedResourceMetadata', () => {
  // RFC 9728 §3.3: `resource` MUST be identical to the identifier the metadata
  // URL was derived from, or the client MUST NOT use the document. A single
  // document served at the bare path cannot legally claim a /mcp resource.
  it.each([
    ['', BASE],
    ['/mcp', `${BASE}/mcp`],
    ['/sse', `${BASE}/sse`],
  ])('document for %j declares resource %j', (path, expected) => {
    expect(protectedResourceMetadata(path, BASE).resource).toBe(expected);
  });

  it('points every document at the same authorization server', () => {
    for (const path of ['', '/mcp', '/sse']) {
      expect(protectedResourceMetadata(path, BASE).authorization_servers).toEqual([BASE]);
    }
  });

  it('keeps each document self-consistent: resource matches its own URL', () => {
    for (const path of ['', '/mcp', '/sse']) {
      const url = protectedResourceMetadataUrl(path, BASE);
      const doc = protectedResourceMetadata(path, BASE);
      // Strip the well-known segment back out; what remains is the identifier
      // the client derived the URL from, and it must equal `resource`.
      expect(url.replace('/.well-known/oauth-protected-resource', '')).toBe(doc.resource);
    }
  });
});

describe('buildResourceChallenge', () => {
  it('names the document for the endpoint being accessed, not the origin', () => {
    expect(buildResourceChallenge('/mcp', BASE)).toBe(
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`
    );
  });

  // The previous version of this test passed BASE (no trailing slash) and so
  // asserted a guarantee it never exercised. Feed it the input that actually
  // breaks: a configured URL ending in "/".
  it.each([`${BASE}/`, `${BASE}//`])('normalises a trailing slash on %j', (configured) => {
    expect(buildResourceChallenge('/mcp', configured)).toBe(
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`
    );
  });

  it('keeps the document self-consistent when the base has a trailing slash', () => {
    // If only one of the two normalised, the client would fetch a document
    // whose `resource` disagreed with the URL it came from — RFC 9728 §3.3
    // says discard it, so the mismatch would be silent and fatal.
    const url = protectedResourceMetadataUrl('/mcp', `${BASE}/`);
    const doc = protectedResourceMetadata('/mcp', `${BASE}/`);
    expect(url.replace('/.well-known/oauth-protected-resource', '')).toBe(doc.resource);
  });
});

describe('sendUnauthorized', () => {
  it('always attaches WWW-Authenticate alongside the 401', () => {
    const res = mockResponse();

    sendUnauthorized(res, { error: 'authentication_required' }, '/mcp');

    expect(res.setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      expect.stringContaining('resource_metadata=')
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'authentication_required' });
  });

  it('scopes the challenge to the endpoint the client hit', () => {
    const mcp = mockResponse();
    const sse = mockResponse();

    sendUnauthorized(mcp, {}, '/mcp');
    sendUnauthorized(sse, {}, '/sse');

    expect(mcp.setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      expect.stringContaining('/.well-known/oauth-protected-resource/mcp')
    );
    expect(sse.setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      expect.stringContaining('/.well-known/oauth-protected-resource/sse')
    );
  });

  it('sets the header before the body is sent', () => {
    const res = mockResponse();
    const order: string[] = [];
    res.setHeader.mockImplementation(() => void order.push('header'));
    res.json.mockImplementation(() => {
      order.push('body');
      return res;
    });

    sendUnauthorized(res, { error: 'project_binding_required' }, '/mcp');

    expect(order).toEqual(['header', 'body']);
  });
});

describe('normaliseBaseUrl', () => {
  it('strips trailing slashes so no consumer has to', async () => {
    // Guarding the two consumers I first noticed left eight others — the AS
    // metadata, the OAuth callback registered with the platform, the
    // project-selection redirect, two authorize URLs in error bodies, the
    // projects URL and the banner. Express matches none of those routes with
    // a doubled slash.
    const { normaliseBaseUrl } = await import('./config.js');

    expect(normaliseBaseUrl('https://mcp.insforge.dev/')).toBe('https://mcp.insforge.dev');
    expect(normaliseBaseUrl('https://mcp.insforge.dev///')).toBe('https://mcp.insforge.dev');
    expect(normaliseBaseUrl('https://mcp.insforge.dev')).toBe('https://mcp.insforge.dev');
    // A path-bearing base keeps its path, loses only the trailing slash.
    expect(normaliseBaseUrl('https://host/base/')).toBe('https://host/base');
  });
});

describe('no advertised URL can contain a doubled slash', () => {
  // Quinn's ask: assert on the URLs we advertise, not on the helper that
  // builds them. A trailing slash on MCP_SERVER_URL used to break the login
  // in at least three separate places, at three different steps — the AS
  // metadata, the project-selection redirect, and the authorize links in 401
  // bodies. Per-consumer patching missed two of them.
  const SLASHED = 'https://mcp.insforge.dev/';

  /** Everything after the scheme, so `https://` itself is not a false hit. */
  const hasDoubledSlash = (url: string) => url.replace(/^[a-z]+:\/\//, '').includes('//');

  it('not in the protected-resource documents', () => {
    for (const path of ['', '/mcp', '/sse']) {
      const doc = protectedResourceMetadata(path, SLASHED);
      expect(hasDoubledSlash(String(doc.resource))).toBe(false);
      for (const as of doc.authorization_servers as string[]) {
        expect(hasDoubledSlash(as)).toBe(false);
      }
    }
  });

  it('not in the metadata URL a client derives', () => {
    for (const path of ['', '/mcp', '/sse']) {
      expect(hasDoubledSlash(protectedResourceMetadataUrl(path, SLASHED))).toBe(false);
    }
  });

  it('not in the WWW-Authenticate challenge', () => {
    for (const path of ['', '/mcp', '/sse']) {
      const challenge = buildResourceChallenge(path, SLASHED);
      const named = challenge.match(/resource_metadata="([^"]+)"/)?.[1] ?? '';
      expect(named).not.toBe('');
      expect(hasDoubledSlash(named)).toBe(false);
    }
  });
});

describe('nothing bypasses the normalisation', () => {
  it('only config.ts reads MCP_SERVER_URL', async () => {
    // publicUrl is normalised where it is defined, so every consumer is safe
    // by construction. The one way to reintroduce the bug is to read the raw
    // environment variable somewhere else, so that is what this forbids.
    const { readdirSync, readFileSync, statSync } = await import('node:fs');
    const { join } = await import('node:path');

    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) {
          walk(full);
          continue;
        }
        if (!full.endsWith('.ts') || full.endsWith('.test.ts')) continue;
        if (full.endsWith('http/config.ts')) continue;
        if (/process\.env\.MCP_SERVER_URL/.test(readFileSync(full, 'utf8'))) offenders.push(full);
      }
    };
    walk('src');

    expect(offenders).toEqual([]);
  });
});
