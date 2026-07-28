import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';
import { buildResourceChallenge, sendUnauthorized } from './auth-challenge.js';

function mockResponse() {
  const res = {
    setHeader: vi.fn(),
    status: vi.fn(() => res),
    json: vi.fn(() => res),
  };
  return res as unknown as Response & typeof res;
}

describe('buildResourceChallenge', () => {
  it('names the protected-resource metadata document', () => {
    expect(buildResourceChallenge('https://mcp.insforge.dev')).toBe(
      'Bearer resource_metadata="https://mcp.insforge.dev/.well-known/oauth-protected-resource"'
    );
  });

  it('does not leave a trailing slash from the public URL', () => {
    // publicUrl is configured without a trailing slash; if that ever changes the
    // metadata URL must not end up with a double slash, which clients reject.
    expect(buildResourceChallenge('https://mcp.insforge.dev')).not.toContain('//.well-known');
  });
});

describe('sendUnauthorized', () => {
  it('always attaches WWW-Authenticate alongside the 401', () => {
    const res = mockResponse();

    sendUnauthorized(res, { error: 'authentication_required' });

    // The header is the whole point: a 401 without it gives a spec-compliant
    // client nothing to discover the authorization server from.
    expect(res.setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      expect.stringContaining('resource_metadata=')
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'authentication_required' });
  });

  it('sets the header before the body is sent', () => {
    const res = mockResponse();
    const order: string[] = [];
    res.setHeader.mockImplementation(() => void order.push('header'));
    res.json.mockImplementation(() => {
      order.push('body');
      return res;
    });

    sendUnauthorized(res, { error: 'project_binding_required' });

    expect(order).toEqual(['header', 'body']);
  });
});
