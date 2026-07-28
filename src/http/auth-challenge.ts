import type { Response } from 'express';
import { SERVER_CONFIG, OAUTH_ENDPOINTS } from './config.js';

/**
 * Build the `WWW-Authenticate` value for an unauthenticated MCP request.
 *
 * RFC 9728 §5.1: a protected resource signals where its metadata lives via a
 * `resource_metadata` parameter on the Bearer challenge. The MCP authorization
 * spec requires this on 401s so a client can discover the authorization server
 * without being told out of band.
 */
export function buildResourceChallenge(publicUrl: string = SERVER_CONFIG.publicUrl): string {
  return `Bearer resource_metadata="${publicUrl}${OAUTH_ENDPOINTS.protectedResource}"`;
}

/**
 * Reject an unauthenticated MCP request with the discovery challenge attached.
 * Without the header a spec-compliant client sees a bare 401 and has nothing
 * to start the OAuth flow from.
 */
export function sendUnauthorized(res: Response, body: Record<string, unknown>): Response {
  res.setHeader('WWW-Authenticate', buildResourceChallenge());
  return res.status(401).json(body);
}
