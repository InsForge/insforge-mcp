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

  it('does not produce a double slash', () => {
    expect(buildResourceChallenge('/mcp', BASE)).not.toContain('//.well-known');
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
