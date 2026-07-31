import 'dotenv/config';
import { createHmac } from 'crypto';
import { program } from 'commander';
import { PACKAGE_VERSION } from '../shared/version.js';

// ============================================================================
// Command Line Arguments
// ============================================================================

program
  .name('insforge-mcp-server')
  .description('HTTP MCP server for Insforge backend-as-a-service')
  .version(PACKAGE_VERSION, '-v, --version')
  // Defaults come from the environment so a container platform's injected
  // PORT/HOST are honoured. An explicit flag still wins: commander only
  // applies a default when the flag is absent.
  .option('--port <number>', 'Port to run HTTP server on', process.env.PORT || '3000')
  .option('--host <string>', 'Host to bind to', process.env.HOST || '127.0.0.1');
program.parse(process.argv);

const cliOptions = program.opts();

// ============================================================================
// Server Configuration
// ============================================================================

/**
 * A base URL with any trailing slash removed.
 *
 * Exported and applied once at the source rather than at each consumer,
 * because there are ten of them — the AS metadata, the OAuth callback we
 * register with the platform, the project-selection redirect, two authorize
 * URLs in error bodies, the projects URL and the startup banner. A configured
 * MCP_SERVER_URL ending in / gave every one a doubled slash, and Express
 * matches none of those routes. Guarding the two I first noticed left the
 * other eight, and left the next consumer free to reintroduce it.
 */
export function normaliseBaseUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

export const SERVER_CONFIG = {
  /**
   * Port to run HTTP server on.
   *
   * Sourced from PORT when no flag is given — every container platform assigns
   * one that way and nothing here was reading it, so a hosted deploy bound
   * 3000 regardless of what it had been told to use.
   */
  port: parseInt(cliOptions.port) || 3000,

  /**
   * Host to bind to.
   *
   * Stays loopback unless asked otherwise: a locally-run binary should not be
   * reachable from the network. A container opts in with --host 0.0.0.0 or
   * HOST, which the start script does explicitly so it is visible rather than
   * implied.
   */
  host: cliOptions.host || '127.0.0.1',

  /** Public URL of this MCP server */
  publicUrl: normaliseBaseUrl(process.env.MCP_SERVER_URL || 'http://localhost:3000'),
} as const;

// ============================================================================
// Insforge Platform Configuration
// ============================================================================

export const INSFORGE_CONFIG = {
  /** Insforge API base URL */
  apiBase: process.env.INSFORGE_API_BASE || 'https://api.insforge.dev',

  /** Insforge frontend URL */
  frontendUrl: process.env.INSFORGE_FRONTEND_URL || 'https://insforge.dev',

  /** OAuth client ID (registered with Insforge platform) */
  clientId: process.env.INSFORGE_CLIENT_ID || '',

  /** OAuth client secret (registered with Insforge platform) */
  clientSecret: process.env.INSFORGE_CLIENT_SECRET || '',

  /** OAuth scopes to request from Insforge */
  oauthScopes: 'user:read organizations:read projects:read projects:write',
} as const;

// ============================================================================
// OAuth Configuration
// ============================================================================

export const OAUTH_CONFIG = {
  /** OAuth callback URL for Insforge OAuth */
  callbackUrl: `${SERVER_CONFIG.publicUrl}/oauth/callback`,

  /** Scopes supported by this MCP server */
  supportedScopes: ['mcp:read', 'mcp:write', 'project:select'],

  /** Grant types supported */
  grantTypes: ['authorization_code'],

  /** Response types supported */
  responseTypes: ['code'],

  /** Code challenge methods supported (only S256 for security) */
  codeChallengesMethods: ['S256'],
} as const;

// ============================================================================
// Client ID Signing Key
// ============================================================================

/**
 * The key that signs client ids, derived rather than configured.
 *
 * No new environment variable: there are three, and a fourth that only this
 * one feature needs would have to be generated, distributed and rotated by
 * hand, and a server that booted without it would fail at the first
 * registration rather than at boot.
 *
 * Derived from INSFORGE_CLIENT_SECRET through an HMAC with a fixed label, so
 * the platform secret itself is never the signing key. That separation matters:
 * a client id is public (it travels in every authorize URL), so its signatures
 * are public samples of whatever key produced them. Deriving means those
 * samples are of a key that can do nothing but sign client ids.
 *
 * Rotating INSFORGE_CLIENT_SECRET invalidates every client id, which is the
 * intended and only revocation mechanism — see client-id.ts.
 */
const CLIENT_ID_KEY_LABEL = 'mcp-client-id-v1';

export function deriveClientIdSigningKey(clientSecret: string): string {
  if (!clientSecret) {
    throw new Error(
      'INSFORGE_CLIENT_SECRET is required: the client id signing key is derived from it'
    );
  }
  return createHmac('sha256', clientSecret).update(CLIENT_ID_KEY_LABEL).digest('base64url');
}

/**
 * Read lazily rather than at module load: config is imported by tests and by
 * the stdio entry point, neither of which has platform credentials, and a
 * throw at import time would take both down for a feature they never use.
 */
export function clientIdSigningKey(): string {
  return deriveClientIdSigningKey(INSFORGE_CONFIG.clientSecret);
}

// ============================================================================
// Authorization State Key
// ============================================================================

/**
 * The key that seals authorization state. Derived, like the client id key, and
 * from the same secret but a DIFFERENT label.
 *
 * The label is the whole point: one compromised or observed value must not help
 * against the other. Same secret, same algorithm, different label gives two keys
 * with no computable relationship — which is what lets a public, signed client
 * id and an encrypted, secret-bearing auth state coexist under one environment
 * variable.
 *
 * 32 bytes exactly, because AES-256-GCM takes a 32-byte key and a shorter or
 * longer one is a throw rather than a silent weakening.
 */
const AUTH_STATE_KEY_LABEL = 'mcp-auth-state-v1';

export function deriveAuthStateKey(clientSecret: string): Buffer {
  if (!clientSecret) {
    throw new Error(
      'INSFORGE_CLIENT_SECRET is required: the authorization state key is derived from it'
    );
  }
  return createHmac('sha256', clientSecret).update(AUTH_STATE_KEY_LABEL).digest();
}

/** Lazy for the same reason as clientIdSigningKey. */
export function authStateKey(): Buffer {
  return deriveAuthStateKey(INSFORGE_CONFIG.clientSecret);
}

/**
 * And a third key, for authorization codes. Same secret, third label.
 *
 * Three purposes, three keys, no relationship between them: a client id is
 * public and signed, an auth state is secret and encrypted, an auth code is a
 * bearer credential in its own right. Sharing one key across all three would
 * mean a weakness in the most exposed use reaches the other two.
 */
const AUTH_CODE_KEY_LABEL = 'mcp-auth-code-v1';

export function deriveAuthCodeKey(clientSecret: string): Buffer {
  if (!clientSecret) {
    throw new Error('INSFORGE_CLIENT_SECRET is required: the authorization code key is derived from it');
  }
  return createHmac('sha256', clientSecret).update(AUTH_CODE_KEY_LABEL).digest();
}

/** Lazy for the same reason as the others. */
export function authCodeKey(): Buffer {
  return deriveAuthCodeKey(INSFORGE_CONFIG.clientSecret);
}

/**
 * And a fourth, for the access token we issue to MCP clients.
 *
 * Fourth purpose, fourth label, no relationship to the other three. This one
 * seals the most valuable envelope we produce — it carries the platform access
 * token — so it is the one that most needs its own key.
 */
const ACCESS_TOKEN_KEY_LABEL = 'mcp-access-token-v1';

export function deriveAccessTokenKey(clientSecret: string): Buffer {
  if (!clientSecret) {
    throw new Error('INSFORGE_CLIENT_SECRET is required: the access token key is derived from it');
  }
  return createHmac('sha256', clientSecret).update(ACCESS_TOKEN_KEY_LABEL).digest();
}

export function accessTokenKey(): Buffer {
  return deriveAccessTokenKey(INSFORGE_CONFIG.clientSecret);
}

// ============================================================================
// Redis Configuration
// ============================================================================
//
// Gone, along with redis.ts and the ioredis dependency. This note stays for one
// release because REDIS_URL / REDIS_HOST are still set on deployed
// environments: they are now READ BY NOTHING. Removing them is safe and does
// nothing; leaving them set is also safe and also does nothing. What is not
// safe is assuming a Redis is still there because the variable is.

// ============================================================================
// Session Configuration
// ============================================================================

/**
 * Positive-integer env override. A zero, a negative or an unparseable value
 * falls back to the default rather than reaching setInterval, which clamps a
 * non-positive delay to 1ms and would spin.
 */
export function positiveIntEnv(value: string | undefined, fallback: number): number {
  const parsed = parseInt(value || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * How often to write a comment frame on an idle SSE stream. Must stay well
 * under the load balancer's idle timeout (60s by default on an AWS ALB) or the
 * stream is closed underneath a connected client.
 */
export const SSE_KEEPALIVE_MS = positiveIntEnv(process.env.MCP_SSE_KEEPALIVE_MS, 25 * 1000);

/**
 * How often to look for sessions to reap.
 *
 * This is no longer housekeeping behind a Redis TTL — it IS session expiry, and
 * nothing else releases a session's memory. Overridable so the sweep can be
 * exercised without waiting minutes.
 */
export const SESSION_SWEEP_MS = positiveIntEnv(process.env.MCP_SESSION_SWEEP_MS, 5 * 60 * 1000);

// SESSION_CONFIG is gone with the store it described: its `ttl` was a duplicate
// of the one in session-manager.ts and its `keyPrefix` named Redis keys that no
// longer exist. Two constants for one timeout is how they drift apart.

// ============================================================================
// Analytics Configuration
// ============================================================================

export const ANALYTICS_CONFIG = {
  /** Mixpanel project token */
  mixpanelToken: process.env.MIXPANEL_TOKEN || '',
} as const;

/**
 * Check if analytics is configured and enabled
 */
export function isAnalyticsConfigured(): boolean {
  return !!ANALYTICS_CONFIG.mixpanelToken && process.env.ENABLE_ANALYTICS !== 'false';
}

// ============================================================================
// MCP Endpoint Paths
// ============================================================================

/**
 * Streamable HTTP Transport (Protocol version 2025-03-26)
 * Modern protocol using a single endpoint for all operations
 */
export const STREAMABLE_HTTP_ENDPOINTS = {
  /** Main MCP endpoint - handles POST (messages), GET (SSE stream), DELETE (close) */
  mcp: '/mcp',
} as const;

/**
 * Legacy SSE Transport (Protocol version 2024-11-05)
 * Deprecated protocol using separate endpoints for SSE stream and messages
 */
export const SSE_ENDPOINTS = {
  /** SSE stream endpoint - GET to establish Server-Sent Events connection */
  sse: '/sse',

  /** Messages endpoint - POST to send messages to server */
  messages: '/messages',
} as const;

// ============================================================================
// OAuth Endpoint Paths
// ============================================================================

export const OAUTH_ENDPOINTS = {
  /** OAuth authorization server metadata (RFC 8414) */
  metadata: '/.well-known/oauth-authorization-server',

  /** OAuth protected resource metadata */
  protectedResource: '/.well-known/oauth-protected-resource',

  /** Dynamic client registration (RFC 7591) */
  register: '/oauth/register',

  /** Authorization endpoint */
  authorize: '/oauth/authorize',

  /** OAuth callback from Insforge */
  callback: '/oauth/callback',

  /** Project selection page */
  selectProject: '/oauth/select-project',

  /** Token endpoint */
  token: '/oauth/token',

  /** Token revocation endpoint */
  revoke: '/oauth/revoke',
} as const;

// ============================================================================
// API Endpoint Paths
// ============================================================================

export const API_ENDPOINTS = {
  /** Health check */
  health: '/health',

  /** List projects */
  projects: '/api/projects',

  /** Bind token to project */
  bindProject: '/api/projects/:projectId/bind',
} as const;

// ============================================================================
// Validation
// ============================================================================

/**
 * Check if OAuth client credentials are configured
 */
export function isOAuthConfigured(): boolean {
  return !!(INSFORGE_CONFIG.clientId && INSFORGE_CONFIG.clientSecret);
}

/**
 * Validate required configuration and log warnings
 */
export function validateConfig(): void {
  if (!isOAuthConfigured()) {
    console.warn('[Config] WARNING: OAuth client credentials not configured.');
    console.warn('[Config] Set INSFORGE_CLIENT_ID and INSFORGE_CLIENT_SECRET environment variables.');
  }

  if (!isAnalyticsConfigured()) {
    console.log('[Config] Analytics not configured. Set MIXPANEL_TOKEN to enable Mixpanel tracking.');
  }
}
