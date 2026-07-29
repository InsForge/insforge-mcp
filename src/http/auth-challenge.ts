import type { Response } from 'express';
import { SERVER_CONFIG, OAUTH_ENDPOINTS } from './config.js';

/**
 * Where the protected-resource metadata for a given endpoint lives.
 *
 * RFC 9728 §3.1 builds the metadata URL by inserting the well-known path
 * *between the host and the resource's path*, so the document describing
 * `https://host/mcp` lives at
 * `https://host/.well-known/oauth-protected-resource/mcp` — not at the bare
 * well-known path. Pass `''` for the origin itself.
 */
/**
 * A configured public URL with a trailing slash would otherwise produce
 * `https://host//.well-known/...`, which no route matches and which a client
 * cannot reconcile with the document it receives. Normalise once, here, so
 * every derived URL and every `resource` value agrees.
 */
function origin(publicUrl: string): string {
  return publicUrl.replace(/\/+$/, '');
}

export function protectedResourceMetadataUrl(
  resourcePath = '',
  publicUrl: string = SERVER_CONFIG.publicUrl
): string {
  return `${origin(publicUrl)}${OAUTH_ENDPOINTS.protectedResource}${resourcePath}`;
}

/**
 * The metadata document for one resource path.
 *
 * `resource` MUST be identical to the identifier the client derived the
 * metadata URL from, or a conforming client MUST NOT use the document
 * (RFC 9728 §3.3). That is why each endpoint gets its own document instead of
 * one shared one: a single document served at the bare well-known path cannot
 * legally claim a `/mcp` resource identifier.
 */
export function protectedResourceMetadata(
  resourcePath = '',
  publicUrl: string = SERVER_CONFIG.publicUrl
): Record<string, unknown> {
  return {
    resource: `${origin(publicUrl)}${resourcePath}`,
    authorization_servers: [publicUrl],
    scopes_supported: ['mcp:read', 'mcp:write'],
  };
}

/**
 * Build the `WWW-Authenticate` value for an unauthenticated request to the
 * endpoint at `resourcePath`.
 *
 * RFC 9728 §5.1: a protected resource signals where its metadata lives via a
 * `resource_metadata` parameter on the Bearer challenge. The MCP authorization
 * spec requires this on 401s so a client can discover the authorization server
 * without being told out of band.
 */
export function buildResourceChallenge(
  resourcePath = '',
  publicUrl: string = SERVER_CONFIG.publicUrl
): string {
  return `Bearer resource_metadata="${protectedResourceMetadataUrl(resourcePath, publicUrl)}"`;
}

/**
 * Reject an unauthenticated MCP request with the discovery challenge attached.
 * Without the header a spec-compliant client sees a bare 401 and has nothing
 * to start the OAuth flow from.
 */
export function sendUnauthorized(
  res: Response,
  body: Record<string, unknown>,
  resourcePath = ''
): Response {
  res.setHeader('WWW-Authenticate', buildResourceChallenge(resourcePath));
  return res.status(401).json(body);
}
