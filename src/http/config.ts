import 'dotenv/config';
import { program } from 'commander';
import { PACKAGE_VERSION } from '../shared/version.js';

// ============================================================================
// Command Line Arguments
// ============================================================================

program
  .name('insforge-mcp-server')
  .description('HTTP MCP server for Insforge backend-as-a-service')
  .version(PACKAGE_VERSION, '-v, --version')
  .option('--port <number>', 'Port to run HTTP server on', '3000')
  .option('--host <string>', 'Host to bind to', '127.0.0.1');
program.parse(process.argv);

const cliOptions = program.opts();

// ============================================================================
// Server Configuration
// ============================================================================

export const SERVER_CONFIG = {
  /** Port to run HTTP server on */
  port: parseInt(cliOptions.port) || 3000,

  /** Host to bind to */
  host: cliOptions.host || '127.0.0.1',

  /** Public URL of this MCP server */
  publicUrl: process.env.MCP_SERVER_URL || 'http://localhost:3000',
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
// Redis Configuration
// ============================================================================

export const REDIS_CONFIG = {
  /** Redis host */
  host: process.env.REDIS_HOST || 'localhost',

  /** Redis port */
  port: parseInt(process.env.REDIS_PORT || '6379'),

  /** Redis password */
  password: process.env.REDIS_PASSWORD || undefined,

  /** Use TLS for Redis connection */
  tls: process.env.REDIS_TLS === 'true',

  /** Use Redis cluster mode */
  cluster: process.env.REDIS_CLUSTER === 'true',
} as const;

// ============================================================================
// Session Configuration
// ============================================================================

/**
 * How often to write a comment frame on an idle SSE stream. Must stay well
 * under the load balancer's idle timeout (60s by default on an AWS ALB) or the
 * stream is closed underneath a connected client.
 */
export const SSE_KEEPALIVE_MS = parseInt(process.env.MCP_SSE_KEEPALIVE_MS || '') || 25 * 1000;

/**
 * How often to reap runtime sessions whose Redis record has expired.
 * Overridable so the reaper can be exercised without waiting minutes.
 */
export const SESSION_SWEEP_MS = parseInt(process.env.MCP_SESSION_SWEEP_MS || '') || 5 * 60 * 1000;

export const SESSION_CONFIG = {
  /** Session TTL in seconds (24 hours) */
  ttl: 24 * 60 * 60,

  /** Redis key prefix for sessions */
  keyPrefix: 'mcp:session:',
} as const;

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
