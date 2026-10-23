import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import { randomUUID, createHash } from 'crypto';
import { pathToFileURL } from 'node:url';
import { realpathSync } from 'node:fs';
import v8 from 'node:v8';

// Transport imports
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

// Local imports
import { getSessionManager, routeForSessionRequest, sessionAcceptsCredential, sessionFingerprint } from './session-manager.js';

import { getOAuthManager, hashToken } from './oauth-manager.js';
import {
  SERVER_CONFIG,
  INSFORGE_CONFIG,
  OAUTH_CONFIG,
  STREAMABLE_HTTP_ENDPOINTS,
  SSE_ENDPOINTS,
  SSE_KEEPALIVE_MS,
  SESSION_SWEEP_MS,
  OAUTH_ENDPOINTS,
  API_ENDPOINTS,
  isOAuthConfigured,
  isAnalyticsConfigured,
  validateConfig,
  clientIdSigningKey,
} from './config.js';
import { renderProjectSelectionPage } from './templates/project-selection.js';
import { getAnalyticsService, extractClientInfo } from './analytics.js';
import { sendUnauthorized, protectedResourceMetadata } from './auth-challenge.js';
import { sendOAuthError, PKCE_REQUIRED_PAGE } from './oauth-error-response.js';
import {
  mintClientId,
  readClientId,
  isRegisteredRedirectUri,
  InvalidClientIdError,
  InvalidRegistrationError,
  type ClientRegistration,
} from './client-id.js';
import {
  authStateCookieName,
  cookieAttributes,
  readCookies,
  isAcceptableClientState,
  MAX_CLIENT_STATE_LENGTH,
} from './auth-state-cookie.js';
import { ACCESS_TOKEN_TTL_SECONDS, accessTokenLifetimeSeconds, readAccessToken, issueAccessToken } from './access-token.js';
import { readRefreshToken } from './refresh-token.js';
import { getProjectKeyCache } from './project-key-cache.js';
import { accessTokenKey, refreshTokenKey } from './config.js';
import { statusForHttpError, isAuthorizationRefusal } from './error-status.js';
import { revokePlatformToken, exchangePlatformCode, refreshPlatformToken, type PlatformTokens } from './insforge-api.js';
import { PACKAGE_VERSION } from '../shared/version.js';

// ============================================================================
// Express App Setup
// ============================================================================

export const app = express();

// Trust proxy headers (X-Forwarded-Proto, X-Forwarded-For, etc.)
// Required for correct protocol detection behind reverse proxies (nginx, AWS ALB, etc.)
app.set('trust proxy', true);

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));

// Parse URL-encoded bodies (for OAuth token endpoint)
app.use(express.urlencoded({ extended: true }));

// CORS and security headers middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization, Mcp-Session-Id, Last-Event-ID');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// ============================================================================
// Helper Functions
// ============================================================================

function isInitializeRequest(body: unknown): boolean {
  if (!body) return false;

  if (typeof body === 'object' && body !== null && 'method' in body) {
    if ((body as { method: string }).method === 'initialize') {
      return true;
    }
  }

  if (Array.isArray(body)) {
    return body.some((req: unknown) =>
      typeof req === 'object' && req !== null && 'method' in req &&
      (req as { method: string }).method === 'initialize'
    );
  }

  return false;
}

/**
 * The sealed state from the request, or null.
 *
 * Every cookie with our name is tried, not just the first. On a shared parent
 * domain a co-tenant can set a cookie of any name for the parent and the
 * browser sends it alongside ours; taking the first match let a neighbour
 * either substitute their value or, with one malformed percent-escape, end
 * every sign-in. A shadowing value simply fails to open here and the next
 * candidate is tried.
 */
async function openStateFromRequest(
  req: Request,
  expectedHandle: string
): Promise<{ sealed: string; authState: NonNullable<Awaited<ReturnType<ReturnType<typeof getOAuthManager>['getAuthorizationState']>>> } | null> {
  const oauthManager = getOAuthManager();
  for (const sealed of readCookies(req.headers.cookie, authStateCookieName(SERVER_CONFIG.publicUrl))) {
    const authState = await oauthManager.getAuthorizationState(sealed, expectedHandle);
    if (authState) return { sealed, authState };
  }
  return null;
}

/**
 * Generate a short, non-reversible fingerprint of a token for logging
 * Uses first 8 chars of SHA-256 hash to identify tokens without exposing them
 */
function tokenFingerprint(token: string): string {
  return createHash('sha256').update(token).digest('hex').substring(0, 8);
}

/**
 * Project information resolved from an OAuth token.
 */
interface ResolvedProject {
  apiKey: string;
  apiBaseUrl: string;
  projectId: string;
  projectName: string;
  userId: string;
  organizationId: string;
  oauthTokenHash: string;
}

/**
 * Three outcomes, not two: 401 when the credential is the problem, 5xx when we
 * could not tell. Reporting a platform fault as 401 drags a user through a
 * browser login for something a retry would fix; reporting a dead credential as
 * 500 tells the client to give up when signing in again is the remedy.
 */
type ProjectResolution =
  | { outcome: 'resolved'; project: ResolvedProject }
  | { outcome: 'unauthorized' }
  | { outcome: 'unavailable' };

/**
 * We could not find out whether this credential is good.
 *
 * 503 rather than 500 because it is specifically temporary, and with
 * `Retry-After` because that is the difference between a client that backs off
 * and one that hammers a platform already in trouble. Deliberately carries NO
 * `WWW-Authenticate`: the header is an instruction to re-run OAuth, and sending
 * it here would produce exactly the pointless browser login this distinction
 * exists to prevent.
 */
function sendUnavailable(res: Response): Response {
  return res
    .status(503)
    .set('Retry-After', '5')
    .json({
      error: 'temporarily_unavailable',
      error_description:
        'Could not reach the InsForge platform to check this session. Your sign-in has not been ' +
        'invalidated — retry shortly.',
    });
}

async function resolveProject(token: string): Promise<ProjectResolution> {
  const oauthManager = getOAuthManager();
  try {
    const project = await oauthManager.resolveProjectFromToken(token);
    return project ? { outcome: 'resolved', project } : { outcome: 'unauthorized' };
  } catch (error) {
    // Nothing may escape this wrapper as a throw. A token that does not open
    // never reaches here (resolveProjectFromToken returns null for that, which
    // is 'unauthorized'); anything that throws is something we could not
    // determine, so it is 'unavailable' and the caller answers 503.
    console.error('[OAuth] Could not determine whether this token is valid:', error);
    return { outcome: 'unavailable' };
  }
}

/**
 * Extract OAuth token from request headers
 */
function extractOAuthToken(req: Request): string | undefined {
  const authHeader = req.headers['authorization'] as string;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return undefined;
}

/**
 * Refuse a request that names a session it was not the one to open.
 *
 * Called by every verb, not just POST: DELETE on the id alone logs someone else
 * out, and GET opens the server->client stream and receives everything pushed
 * for that session. Returns true when it has already answered.
 *
 * Call it only AFTER the handler has established that this process holds the
 * session. Before that it would authenticate ahead of routing, and a client with
 * a dead session plus a stale token would get 401 where it needs the 404 that
 * tells it to start over.
 */
function credentialMatchesSession(req: Request, sessionId: string): boolean {
  const stored = getSessionManager().getSessionData(sessionId)?.oauthTokenHash;
  const presentedToken = extractOAuthToken(req);
  // The FULL sha256, never tokenFingerprint's 8 chars — see
  // sessionAcceptsCredential for why that mistake logs everyone out.
  const presented = presentedToken ? hashToken(presentedToken) : undefined;
  return sessionAcceptsCredential(stored, presented);
}

function refuseMismatchedCredential(req: Request, res: Response, sessionId: string): boolean {
  if (credentialMatchesSession(req, sessionId)) return false;

  console.log(
    `[Streamable HTTP] Session ${sessionFingerprint(sessionId)} refused: ` +
      'credential does not match the one it was opened with'
  );

  // 404, not 401. A 401 tells the client to re-run OAuth; a client that just did
  // so holds a NEW token and the same old session id, so 401 sends it round the
  // loop forever. 404 is the recovery the routing path already gives: start a
  // new session. It also leaks less: "not found" and "not yours" read the same.
  res.status(404).json({
    error: 'Session not found',
    error_description:
      'This session is not held by the server — it expired, or the server restarted. ' +
      'Send an initialize request to start a new one.',
  });
  return true;
}

/**
 * Extract legacy headers for backwards compatibility
 */
function extractLegacyHeaders(req: Request): { apiKey?: string; apiBaseUrl?: string } {
  return {
    apiKey: req.headers['x-api-key'] as string,
    apiBaseUrl: req.headers['x-base-url'] as string,
  };
}

/**
 * Heap numbers for the health payload. V8's own limit, not RSS, is what decides
 * how long the process lives, so it is published alongside usage.
 */
function heapStats() {
  const { heap_size_limit, used_heap_size } = v8.getHeapStatistics();
  return {
    heapUsedMb: Math.round(used_heap_size / 1024 / 1024),
    heapLimitMb: Math.round(heap_size_limit / 1024 / 1024),
    heapUsedPct: Math.round((used_heap_size / heap_size_limit) * 100),
    rssMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
  };
}

// ============================================================================
// Health & Discovery Endpoints
// ============================================================================

app.get(API_ENDPOINTS.health, (_req: Request, res: Response) => {
  const sessionManager = getSessionManager();
  const stats = sessionManager.getStats();

  res.json({
    status: 'ok',
    server: 'insforge-mcp',
    version: PACKAGE_VERSION,
    protocols: {
      streamableHttp: '2025-03-26',
      sse: '2024-11-05 (deprecated)',
    },
    sessions: stats,
    memory: heapStats(),
    authentication: 'OAuth Bearer Token',
  });
});

// OAuth 2.0 Authorization Server Metadata (RFC 8414)
// Uses SERVER_CONFIG.publicUrl as the canonical base URL to avoid host header spoofing
app.get(OAUTH_ENDPOINTS.metadata, (_req: Request, res: Response) => {
  const baseUrl = SERVER_CONFIG.publicUrl;

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}${OAUTH_ENDPOINTS.authorize}`,
    token_endpoint: `${baseUrl}${OAUTH_ENDPOINTS.token}`,
    revocation_endpoint: `${baseUrl}${OAUTH_ENDPOINTS.revoke}`,
    registration_endpoint: `${baseUrl}${OAUTH_ENDPOINTS.register}`,
    response_types_supported: OAUTH_CONFIG.responseTypes,
    grant_types_supported: OAUTH_CONFIG.grantTypes,
    code_challenge_methods_supported: OAUTH_CONFIG.codeChallengesMethods,
    scopes_supported: OAUTH_CONFIG.supportedScopes,
  });
});

// OAuth 2.0 Protected Resource Metadata (for MCP discovery)
// The resource field must match what the client is trying to access
// Uses SERVER_CONFIG.publicUrl as the canonical base URL to avoid host header spoofing
// One document per protected endpoint. RFC 9728 §3.1 derives the metadata URL
// by inserting the well-known path between the host and the resource's path, and
// §3.3 requires the `resource` value to be identical to the identifier that URL
// was derived from — a client MUST discard a document that fails that check. So
// the /mcp document lives under /.well-known/oauth-protected-resource/mcp and the
// bare path describes the origin.
app.get(
  `${OAUTH_ENDPOINTS.protectedResource}${STREAMABLE_HTTP_ENDPOINTS.mcp}`,
  (_req: Request, res: Response) => {
    res.json(protectedResourceMetadata(STREAMABLE_HTTP_ENDPOINTS.mcp));
  }
);

app.get(
  `${OAUTH_ENDPOINTS.protectedResource}${SSE_ENDPOINTS.sse}`,
  (_req: Request, res: Response) => {
    res.json(protectedResourceMetadata(SSE_ENDPOINTS.sse));
  }
);

// Kept for clients that probe the origin rather than following the challenge.
app.get(OAUTH_ENDPOINTS.protectedResource, (_req: Request, res: Response) => {
  res.json(protectedResourceMetadata());
});

// ============================================================================
// OAuth 2.0 Endpoints
// ============================================================================

/**
 * A registration metadata field the client may send as an array, or not at all,
 * or as something else entirely — it is request body, so it is not typed.
 * Anything that is not an array of strings is treated as absent, which lands on
 * the defaults below rather than on a 400: the goal is to refuse values we
 * cannot honour, not to police shapes the caller never meant to send.
 */
function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/**
 * OAuth Dynamic Client Registration (RFC 7591)
 */
app.post(OAUTH_ENDPOINTS.register, (req: Request, res: Response) => {
  const {
    client_name,
    redirect_uris,
    grant_types,
    response_types,
    token_endpoint_auth_method,
    scope,
  } = req.body;

  const clientName = typeof client_name === 'string' && client_name ? client_name : 'MCP Client';

  // A registration response is the server asserting what it will honour, so an
  // unsupported grant_type is refused here, where the caller is listening, rather
  // than discovered at the first token request in front of a user.
  const unsupportedGrants = asStringArray(grant_types).filter(
    (value) => !(OAUTH_CONFIG.grantTypes as readonly string[]).includes(value)
  );
  if (unsupportedGrants.length > 0) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description:
        `grant_types contains values this server does not support: ${unsupportedGrants.join(', ')}. ` +
        `Supported: ${OAUTH_CONFIG.grantTypes.join(', ')}.`,
    });
  }

  const unsupportedResponses = asStringArray(response_types).filter((value) => value !== 'code');
  if (unsupportedResponses.length > 0) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description:
        `response_types contains values this server does not support: ${unsupportedResponses.join(', ')}. ` +
        'Supported: code.',
    });
  }

  // The registration is carried by the id itself, so nothing is written here.
  // mintClientId validates redirect_uris (count, absoluteness, scheme,
  // loopback-only plaintext http), so this route does not pre-check the array.
  let clientId: string;
  try {
    clientId = mintClientId(
      { redirect_uris, client_name: clientName },
      clientIdSigningKey()
    );
  } catch (error) {
    if (error instanceof InvalidRegistrationError) {
      return res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: error.message,
      });
    }
    // A missing signing key is our misconfiguration, not the client's.
    console.error('[OAuth] Could not mint a client id:', error);
    return sendOAuthError(req, res, 500, {
      error: 'server_error',
      error_description: 'Client registration is not available on this server.',
    });
  }

  // JSON.stringify, not interpolation: client_name is caller-supplied and only
  // length-bounded, so a newline in it forges log lines — an attacker-chosen
  // "[OAuth] ..." entry that reads exactly like ours. Quoting also makes
  // trailing whitespace and empty names visible instead of silent.
  console.log(`[OAuth] Registered new client (${JSON.stringify(clientName)})`);

  res.status(201).json({
    client_id: clientId,
    client_name: clientName,
    redirect_uris,
    grant_types: grant_types || OAUTH_CONFIG.grantTypes,
    response_types: response_types || ['code'],
    token_endpoint_auth_method: token_endpoint_auth_method || 'none',
    scope: scope || 'mcp:read mcp:write',
  });
});

/**
 * OAuth Authorization Endpoint
 * Redirects to Insforge OAuth for user authentication
 */
app.get(OAUTH_ENDPOINTS.authorize, async (req: Request, res: Response) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  if (!isOAuthConfigured()) {
    return sendOAuthError(req, res, 500, {
      error: 'server_error',
      error_description: 'OAuth client credentials not configured. Set INSFORGE_CLIENT_ID and INSFORGE_CLIENT_SECRET.',
    });
  }

  if (!client_id || !redirect_uri || !response_type) {
    return sendOAuthError(
      req,
      res,
      400,
      {
        error: 'invalid_request',
        error_description: 'Missing required parameters: client_id, redirect_uri, response_type',
      },
      {
        // Distinct from the redirect_uri wording: reaching authorize with no
        // parameters at all is usually a person opening the URL by hand, and
        // telling them to reinstall would be wrong.
        heading: 'There is nothing to sign in to here',
        message:
          'This page is the middle of a sign-in that a tool starts for you. Opening it ' +
          'directly does nothing. Start the connection from your editor or client instead.',
        action: undefined,
      }
    );
  }

  // Default scope if not provided (scope is optional per OAuth 2.0 spec)
  const resolvedScope = (scope as string) || OAUTH_CONFIG.supportedScopes.join(' ');

  if (!isAcceptableClientState(state)) {
    // The client's own `state` rides inside our sealed cookie, so an unbounded
    // one is an unbounded cookie. Rejected here, where the client is listening,
    // rather than at the callback where only a browser would see it.
    return res.status(400).json({
      error: 'invalid_request',
      error_description: `state must be at most ${MAX_CLIENT_STATE_LENGTH} characters`,
    });
  }

  if (!code_challenge) {
    // Refused here, not at the end of the flow: authorization codes are
    // stateless and cannot be single-use, so for its lifetime a leaked code is
    // redeemable by anyone unless bound to a verifier. PKCE is that binding. It
    // defends against interception, not reuse: whoever holds the verifier can
    // redeem the same code again until it expires (exchangeCode in
    // oauth-manager.ts has nothing to delete). And the MCP client reads this
    // response but never the one after the browser steps. PKCE_REQUIRED_PAGE
    // overrides the invalid_request copy because that copy names a cause (an
    // app restarted on a different port) that is true at the redirect_uri site
    // below and false here.
    return sendOAuthError(
      req,
      res,
      400,
      {
        error: 'invalid_request',
        error_description:
          'code_challenge is required. This server advertises S256 as its only ' +
          'code_challenge_method and issues authorization codes that carry their own state, ' +
          'so PKCE is what makes a code safe to accept.',
      },
      PKCE_REQUIRED_PAGE
    );
  }

  if (response_type !== 'code') {
    return sendOAuthError(req, res, 400, {
      error: 'unsupported_response_type',
      error_description: 'Only response_type=code is supported',
    });
  }

  // Recover the registration from the id. The signature is what makes this
  // trustworthy: anyone can read a client id, only this server can mint one, so
  // a redirect_uri that verifies is one we approved at registration.
  let registration: ClientRegistration;
  try {
    registration = readClientId(client_id as string, clientIdSigningKey());
  } catch (error) {
    if (!(error instanceof InvalidClientIdError)) {
      // A missing or unreadable signing key — our problem, not the caller's,
      // and it must not be reported as an unknown client.
      console.error('[OAuth] Could not read client id:', error);
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Client registration is not available on this server.',
      });
    }
    // Nothing here can recover automatically: the MCP SDK only re-registers on
    // an invalid_client from the token endpoint or from registration, and it
    // never sees this response — the browser does. So the person holding the
    // tab is told how to act.
    console.log('[OAuth] Client id at authorize did not verify');
    return sendOAuthError(req, res, 400, {
      error: 'invalid_client',
      error_description: 'Unknown client_id. Register client first via /oauth/register.',
    });
  }

  // Exact match against what the client registered, per RFC 6749 §3.1.2.3.
  // Anything looser is authorization-code theft: the code would be delivered to
  // whatever URI the request named.
  if (!isRegisteredRedirectUri(registration, redirect_uri)) {
    return sendOAuthError(req, res, 400, {
      error: 'invalid_request',
      error_description: 'redirect_uri does not match any registered redirect URIs for this client.',
    });
  }

  try {
    const oauthManager = getOAuthManager();

    const { handle, sealedState, insforgeCodeChallenge } = await oauthManager.createAuthorizationState({
      redirectUri: redirect_uri as string,
      scope: resolvedScope,
      state: state as string | undefined,
      codeChallenge: code_challenge as string | undefined,
      codeChallengeMethod: code_challenge_method as string | undefined,
    });

    const authUrl = new URL(`${INSFORGE_CONFIG.apiBase}/api/oauth/v1/authorize`);
    authUrl.searchParams.set('client_id', INSFORGE_CONFIG.clientId);
    authUrl.searchParams.set('redirect_uri', OAUTH_CONFIG.callbackUrl);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', INSFORGE_CONFIG.oauthScopes);
    // The handle, not the record. The platform stores `state` in a 255-char
    // column; the record itself rides in a cookie on our own origin.
    res.cookie(authStateCookieName(SERVER_CONFIG.publicUrl), sealedState, cookieAttributes(SERVER_CONFIG.publicUrl));
    authUrl.searchParams.set('state', handle);
    authUrl.searchParams.set('code_challenge', insforgeCodeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    console.log(`[OAuth] Redirecting to Insforge OAuth: ${authUrl.toString()}`);
    res.redirect(authUrl.toString());
  } catch (error) {
    // The entire GET is a browser navigation, so a throw anywhere inside it
    // must render as a page, not raw JSON.
    console.error('OAuth authorize error:', error);
    sendOAuthError(req, res, statusForHttpError(error), {
      error: 'server_error',
      error_description: 'Failed to initiate authorization',
    });
  }
});

/**
 * OAuth Callback Endpoint
 * Called by Insforge OAuth after user authenticates
 */
app.get(OAUTH_ENDPOINTS.callback, async (req: Request, res: Response) => {
  const { code, state, error, error_description } = req.query;

  const oauthManager = getOAuthManager();

  if (error) {
    console.error('[OAuth] Insforge returned error:', error, error_description);
    getAnalyticsService().trackOAuthFailure({
      errorType: 'insforge_error',
      errorDescription: (error_description as string) || (error as string) || 'Unknown Insforge error',
      endpoint: '/oauth/callback',
    });
    const authState = state ? (await openStateFromRequest(req, state as string))?.authState ?? null : null;

    if (authState?.redirectUri) {
      const redirectUrl = new URL(authState.redirectUri);
      redirectUrl.searchParams.set('error', error as string);
      if (error_description) {
        redirectUrl.searchParams.set('error_description', error_description as string);
      }
      if (authState.state) {
        redirectUrl.searchParams.set('state', authState.state);
      }
      return res.redirect(redirectUrl.toString());
    }

    // No registered redirect to bounce the error back to, so this ends in the
    // user's tab. The callback is always a browser navigation (the platform
    // redirecting them here), so the answer is a page, not JSON.
    return sendOAuthError(req, res, 400, {
      error: error as string,
      error_description: error_description as string | undefined,
    });
  }

  if (!code || !state) {
    getAnalyticsService().trackOAuthFailure({
      errorType: 'invalid_request',
      errorDescription: 'Missing required parameters: code, state',
      endpoint: '/oauth/callback',
    });
    return sendOAuthError(
      req,
      res,
      400,
      { error: 'invalid_request', error_description: 'Missing required parameters: code, state' },
      {
        heading: 'This sign-in did not come back complete',
        message:
          'The sign-in was interrupted before it finished. Starting it again from your ' +
          'editor or client is all that is needed.',
        action: undefined,
      }
    );
  }

  try {
    // The record is in our cookie; the platform only echoes the handle. Both
    // are required, and they have to name the same authorization.
    const authState = (await openStateFromRequest(req, state as string))?.authState ?? null;
    if (!authState) {
      getAnalyticsService().trackOAuthFailure({
        errorType: 'invalid_request',
        errorDescription: 'Invalid or expired state',
        endpoint: '/oauth/callback',
      });
      return sendOAuthError(
        req,
        res,
        400,
        { error: 'invalid_request', error_description: 'Invalid or expired state' },
        {
          heading: 'This sign-in took too long',
          message:
            'Sign-ins expire after a few minutes, and this one has. Start it again from ' +
            'your editor or client — nothing is wrong with your account.',
          action: undefined,
        }
      );
    }

    console.log('[OAuth] Exchanging code for tokens...');

    // A throw means no usable response was obtained (fetch failed, timed out,
    // or the body was unparseable): 503 with Retry-After. A parsed body with an
    // `error` field means the platform answered; ordinary grant errors are a
    // 400, while invalid_client and unauthorized_client are a 503 because they
    // identify THIS SERVER's credentials. /oauth/authorize is unauthenticated,
    // so a stranger can reach this exchange.
    let tokens: PlatformTokens;
    try {
      tokens = await exchangePlatformCode({
        code: code as string,
        redirectUri: OAUTH_CONFIG.callbackUrl,
        clientId: INSFORGE_CONFIG.clientId,
        clientSecret: INSFORGE_CONFIG.clientSecret,
        codeVerifier: authState.insforgeCodeVerifier,
      });
    } catch (error) {
      console.error('[OAuth] Could not reach the platform to exchange the code:', error);
      getAnalyticsService().trackOAuthFailure({
        errorType: 'temporarily_unavailable',
        errorDescription: 'Token exchange could not reach the platform',
        endpoint: '/oauth/callback',
      });
      res.set('Retry-After', '5');
      return sendOAuthError(
        req,
        res,
        503,
        {
          error: 'temporarily_unavailable',
          // Deliberately not the raw error: "fetch failed" is Node talking to
          // itself and tells the person nothing.
          error_description:
            'The InsForge platform could not be reached to complete this sign-in.',
        },
        {
          heading: 'InsForge could not be reached',
          message:
            'This is temporary and nothing is wrong with your account or your editor. ' +
            'Wait a moment and start the sign-in again.',
          action: undefined,
        }
      );
    }

    // Same distinction as the refresh grant. `invalid_client` means the platform
    // rejected OUR credentials (a wrong INSFORGE_CLIENT_SECRET), not the user's
    // sign-in; telling the person their sign-in failed sends them round a loop
    // that cannot terminate until an operator fixes the config.
    if (tokens.error === 'invalid_client' || tokens.error === 'unauthorized_client') {
      console.error(
        '[OAuth] The platform rejected OUR client credentials during sign-in. ' +
          'INSFORGE_CLIENT_ID/SECRET are wrong for this deployment — no user action ' +
          'can fix this.'
      );
      getAnalyticsService().trackOAuthFailure({
        errorType: 'server_error',
        errorDescription: 'Platform rejected our client credentials at the callback',
        endpoint: '/oauth/callback',
      });
      res.set('Retry-After', '30');
      return sendOAuthError(
        req,
        res,
        503,
        {
          error: 'temporarily_unavailable',
          error_description: 'This server cannot complete sign-ins right now.',
        },
        {
          heading: 'Sign-in is temporarily unavailable',
          message:
            'This is a problem on our side, not with your account or your editor, and ' +
            'retrying now will not help. We can see it; try again in a few minutes.',
          action: undefined,
        }
      );
    }

    if (tokens.error || !tokens.access_token) {
      console.error('[OAuth] Token exchange error:', tokens);
      getAnalyticsService().trackOAuthFailure({
        errorType: 'token_exchange_failed',
        errorDescription: 'Token exchange failed',
        endpoint: '/oauth/callback',
      });
      return sendOAuthError(
        req,
        res,
        400,
        {
          error: 'token_exchange_failed',
          error_description: tokens.error_description || tokens.error || 'No access token returned',
        },
        {
          heading: 'Sign-in could not be completed',
          message:
            'The InsForge platform did not return a token for this sign-in. Trying again ' +
            'usually works; if it does not, the details below are what support will ask for.',
          action: undefined,
        }
      );
    }

    console.log('[OAuth] Token received, redirecting to project selection...');

    // The tokens ride inside the sealed state, not in a row keyed by it, so the
    // sealed string changes here while the handle does not.
    const stateWithToken = oauthManager.attachPlatformToken(
      authState,
      tokens.access_token,
      tokens.refresh_token
    );

    // Same shape as authorize: the record replaces the cookie, the URL carries
    // only the handle. The handle is unchanged, so the two halves still match.
    res.cookie(authStateCookieName(SERVER_CONFIG.publicUrl), stateWithToken, cookieAttributes(SERVER_CONFIG.publicUrl));
    res.redirect(
      `${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.selectProject}?state_id=${encodeURIComponent(authState.handle)}`
    );
  } catch (error) {
    console.error('OAuth callback error:', error);
    getAnalyticsService().trackOAuthFailure({
      errorType: 'server_error',
      errorDescription: 'Failed to process callback',
      endpoint: '/oauth/callback',
    });
    // The callback is a browser navigation end to end, so the outer catch
    // renders a page like every branch inside it.
    sendOAuthError(req, res, statusForHttpError(error), {
      error: 'server_error',
      error_description: error instanceof Error ? error.message : 'Failed to process callback',
    });
  }
});

/**
 * Project Selection Page (GET)
 */
app.get(OAUTH_ENDPOINTS.selectProject, async (req: Request, res: Response) => {
  const { state_id } = req.query;

  if (!state_id) {
    return res.status(400).send('Missing state_id parameter');
  }

  try {
    const oauthManager = getOAuthManager();

    const authState = (await openStateFromRequest(req, state_id as string))?.authState ?? null;
    if (!authState) {
      return res.status(400).send('Session expired. Please start the authorization process again.');
    }
    const token = authState.platformAccessToken;
    if (!token) {
      // A state that never went through the callback. Same message: from the
      // person's side these are the same event — a sign-in that did not finish.
      return res.status(400).send('Session expired. Please start the authorization process again.');
    }

    const projectGroups = await oauthManager.getAvailableProjects(token);

    res.send(renderProjectSelectionPage({
      stateId: state_id as string,
      projectGroups,
      selectProjectEndpoint: OAUTH_ENDPOINTS.selectProject,
    }));
  } catch (error) {
    console.error('Project selection page error:', error);
    res.status(statusForHttpError(error)).send('Failed to load projects. Please try again.');
  }
});

/**
 * Project Selection Handler (POST)
 */
app.post(OAUTH_ENDPOINTS.selectProject, async (req: Request, res: Response) => {
  const { state_id, project_id } = req.body;

  if (!state_id || !project_id) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required parameters: state_id, project_id',
    });
  }

  try {
    const oauthManager = getOAuthManager();

    const opened = await openStateFromRequest(req, state_id as string);
    const sealed = opened?.sealed;
    const authState = opened?.authState ?? null;
    if (!sealed || !authState?.platformAccessToken) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid or expired state',
      });
    }
    const token = authState.platformAccessToken;

    const code = await oauthManager.createAuthorizationCode(
      sealed,
      state_id as string,
      token,
      project_id as string
    );

    // The record was never stored server-side, but the browser still holds the
    // cookie. Clearing it on completion is cheap defence in depth: the sealed
    // state is replayable inside its ten minutes, and there is no reason to
    // leave a usable copy in the browser once the flow has finished.
    res.clearCookie(authStateCookieName(SERVER_CONFIG.publicUrl), { path: '/' });

    const redirectUrl = new URL(authState.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (authState.state) {
      redirectUrl.searchParams.set('state', authState.state);
    }

    console.log(`[OAuth] Authorization complete, redirecting to client: ${redirectUrl.toString()}`);
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('Project selection error:', error);
    res.status(statusForHttpError(error)).json({
      error: 'server_error',
      error_description: error instanceof Error ? error.message : 'Failed to process project selection',
    });
  }
});

/**
 * OAuth Token Endpoint
 */
app.post(OAUTH_ENDPOINTS.token, async (req: Request, res: Response) => {
  const { grant_type, code, redirect_uri, code_verifier } = req.body;

  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) {
      getAnalyticsService().trackOAuthFailure({
        errorType: 'invalid_request',
        errorDescription: 'Missing required parameters: code, redirect_uri',
        endpoint: '/oauth/token',
      });
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters: code, redirect_uri',
      });
    }

    try {
      const oauthManager = getOAuthManager();
      const { accessToken, refreshToken } = await oauthManager.exchangeCode(
        code as string,
        redirect_uri as string,
        code_verifier as string | undefined
      );

      getAnalyticsService().trackOAuthSuccess({
        clientId: req.body.client_id || 'unknown',
        scope: 'mcp:read mcp:write',
      });

      // The platform token sealed inside has its own expiry, and whichever runs
      // out first ends the session, so advertise the real minimum rather than
      // our ceiling. A flat 24h would have a client retry a dead credential for
      // hours instead of signing in again.
      const payload = readAccessToken(accessToken, accessTokenKey());
      const expiresIn = payload
        ? accessTokenLifetimeSeconds(payload)
        : ACCESS_TOKEN_TTL_SECONDS;

      // Omitted, not `undefined`, when the code carried no refresh token.
      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        ...(refreshToken ? { refresh_token: refreshToken } : {}),
        scope: 'mcp:read mcp:write',
      });
    } catch (error) {
      console.error('OAuth token error:', error);
      getAnalyticsService().trackOAuthFailure({
        errorType: 'invalid_grant',
        errorDescription: 'Invalid authorization code',
        endpoint: '/oauth/token',
      });
      res.status(400).json({
        error: 'invalid_grant',
        error_description: error instanceof Error ? error.message : 'Invalid authorization code',
      });
    }
  } else if (grant_type === 'refresh_token') {
    // The platform token sealed in our access token is a one-hour JWT, so this
    // grant is the only way back without a browser.
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameter: refresh_token',
      });
    }

    // Null covers expired, forged, and sealed under a rotated secret alike —
    // deliberately one answer, since a caller able to tell them apart would be
    // an oracle. All of them mean the same thing to a client: sign in again.
    const payload = readRefreshToken(refresh_token as string, refreshTokenKey());
    if (!payload) {
      getAnalyticsService().trackOAuthFailure({
        errorType: 'invalid_grant',
        errorDescription: 'Refresh token is expired or not ours',
        endpoint: '/oauth/token',
      });
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'This refresh token has expired or is not valid. Sign in again.',
      });
    }

    let tokens: PlatformTokens;
    try {
      tokens = await refreshPlatformToken({
        refreshToken: payload.platformRefreshToken,
        clientId: INSFORGE_CONFIG.clientId,
        clientSecret: INSFORGE_CONFIG.clientSecret,
      });
    } catch (error) {
      // Could not reach the platform, which is not the client's fault and may
      // work on the next attempt — the one case here that must NOT tell someone
      // to sign in again.
      console.error('[OAuth] Could not reach the platform to refresh:', error);
      res.set('Retry-After', '5');
      return res.status(503).json({
        error: 'temporarily_unavailable',
        error_description: 'The InsForge platform could not be reached. Try again shortly.',
      });
    }

    // The platform declining OUR credentials (`invalid_client`, 401, when
    // INSFORGE_CLIENT_SECRET is wrong) is not the user's grant expiring.
    // Reported as invalid_grant it tells every connected user to sign in again,
    // and every new sign-in fails the same way until the config is fixed.
    if (tokens.error === 'invalid_client') {
      console.error(
        '[OAuth] The platform rejected OUR client credentials on refresh. ' +
          'INSFORGE_CLIENT_ID/SECRET are wrong for this deployment — this is not the ' +
          "user's sign-in expiring."
      );
      getAnalyticsService().trackOAuthFailure({
        errorType: 'server_error',
        errorDescription: 'Platform rejected our client credentials on refresh',
        endpoint: '/oauth/token',
      });
      // Retryable, and deliberately NOT a re-authentication prompt: nothing the
      // person does fixes our configuration, and asking them to try is how one
      // bad PATCH becomes a support queue.
      res.set('Retry-After', '30');
      return res.status(503).json({
        error: 'temporarily_unavailable',
        error_description: 'This server cannot renew sign-ins right now. Try again shortly.',
      });
    }

    if (tokens.error || !tokens.access_token) {
      // The platform answered and declined the GRANT: gone, revoked, or past its
      // thirty days. That one IS sign in again.
      getAnalyticsService().trackOAuthFailure({
        errorType: 'invalid_grant',
        errorDescription: 'Platform refused the refresh token',
        endpoint: '/oauth/token',
      });
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'This sign-in can no longer be renewed. Sign in again.',
      });
    }

    const accessToken = issueAccessToken(
      {
        userId: payload.userId,
        platformAccessToken: tokens.access_token,
        projectId: payload.projectId,
      },
      accessTokenKey()
    );

    const refreshed = readAccessToken(accessToken, accessTokenKey());
    getAnalyticsService().trackOAuthSuccess({
      clientId: req.body.client_id || 'unknown',
      scope: 'mcp:read mcp:write',
    });

    // The SAME refresh token back, not a new one. The platform keeps its own on
    // refresh, so ours still names a live grant, and re-sealing would hand the
    // client a different string for no change in what it authorises.
    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: refreshed ? accessTokenLifetimeSeconds(refreshed) : ACCESS_TOKEN_TTL_SECONDS,
      refresh_token,
      scope: 'mcp:read mcp:write',
    });
  } else {
    getAnalyticsService().trackOAuthFailure({
      errorType: 'unsupported_grant_type',
      errorDescription: 'Only authorization_code grant type is supported',
      endpoint: '/oauth/token',
    });
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code grant type is supported',
    });
  }
});

/**
 * OAuth Revocation Endpoint
 */
app.post(OAUTH_ENDPOINTS.revoke, async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing token parameter',
    });
  }

  // Revoke the thing that actually grants access: the platform token sealed
  // inside. Dropping the cached project key alone leaves the bearer working for
  // its full lifetime, since the next request re-fetches the key. Do not add a
  // local revocation marker instead: that is a per-token store consulted on
  // every request, which this design exists to avoid.
  const payload = readAccessToken(token as string, accessTokenKey());

  if (!payload) {
    // Not a token we issued, or already expired. RFC 7009 §2.2: answer 200
    // anyway, so this endpoint cannot be used to probe which tokens are real.
    // Nothing to revoke and nothing went wrong.
    return res.status(200).send();
  }

  // Drop the cached keys first, and unconditionally. It is local, it cannot
  // fail, and it must happen even if the upstream call below does not — a
  // revocation that half-worked should still stop us serving a key we already
  // hold.
  getProjectKeyCache().forgetUser(payload.userId);

  try {
    await revokePlatformToken(payload.platformAccessToken, INSFORGE_CONFIG.clientId);
    console.log(`[OAuth] Platform token revoked for ${payload.userId}`);
    return res.status(200).send();
  } catch (error) {
    // NOT a 200. RFC 7009's blanket success is about not leaking which tokens
    // exist, not licence to report a failed revocation as one that worked. This
    // does let a failure distinguish "was ours" from "was not", but only when
    // the platform is already failing, and it is not attacker-triggerable.
    console.error(`[OAuth] FAILED to revoke the platform token for ${payload.userId}:`, error);

    // The same classification as everywhere else, because the caller's next
    // move differs the same way: a platform that could not be reached is worth
    // retrying, and a platform that refused our client credentials is our
    // misconfiguration and retrying will not help.
    if (isAuthorizationRefusal(error)) {
      return res.status(500).json({
        error: 'server_error',
        error_description:
          'This server could not authenticate itself to the platform to revoke the token. ' +
          'The token may still be usable. This is a server misconfiguration, not something ' +
          'retrying will fix.',
      });
    }

    return res
      .status(503)
      .set('Retry-After', '5')
      .json({
        error: 'temporarily_unavailable',
        error_description:
          'The platform could not be reached to revoke this token. It may still be usable — retry.',
      });
  }
});

// ============================================================================
// Project API Endpoints
// ============================================================================

/**
 * Get available projects for the authenticated user
 */
app.get(API_ENDPOINTS.projects, async (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'] as string;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);

  // Unseal first: the bearer is a sealed envelope, and the platform must
  // receive the platform token inside it, never our string.
  const payload = readAccessToken(token, accessTokenKey());
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  try {
    const oauthManager = getOAuthManager();
    const projects = await oauthManager.getAvailableProjects(payload.platformAccessToken);
    res.json({ organizations: projects });
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(statusForHttpError(error)).json({
      error: 'Failed to get projects',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Bind token to a specific project
 */
app.post(API_ENDPOINTS.bindProject, async (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'] as string;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);
  const projectId = req.params.projectId as string;

  // A token cannot be re-pointed at another project: the project is sealed
  // inside the token the client already holds. Silently doing nothing would
  // look like success, and issuing a NEW token here would hand a caller a
  // credential through an endpoint that never authenticated anyone.
  try {
    const payload = readAccessToken(token, accessTokenKey());
    if (!payload) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    if (payload.projectId === projectId) {
      // Already there. Idempotent rather than an error: a client retrying is
      // not making a mistake. The id and nothing else: name and organization
      // are display data that do not live in the credential (access-token.ts),
      // and re-fetching them here would put a platform round-trip in the path
      // of an endpoint that answers purely from the token.
      return res.json({
        success: true,
        project: { id: payload.projectId },
        message: 'This token is already scoped to that project.',
      });
    }

    return res.status(409).json({
      error: 'Token is scoped to a different project',
      details:
        `This token is scoped to ${payload.projectId} and cannot be re-pointed: the project ` +
        'is part of the token rather than a server-side record. Authorize again to get a token ' +
        'for another project.',
      currentProjectId: payload.projectId,
    });
  } catch (error) {
    console.error('Bind project error:', error);
    res.status(statusForHttpError(error)).json({
      error: 'Failed to bind project',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// ============================================================================
// Streamable HTTP Transport (Protocol version 2025-03-26)
// Modern MCP protocol using a single endpoint
// ============================================================================

/**
 * POST /mcp - Handle MCP messages (initialize, tool calls, etc.)
 */
app.post(STREAMABLE_HTTP_ENDPOINTS.mcp, async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const sessionManager = getSessionManager();

  const oauthToken = extractOAuthToken(req);
  const { apiKey: legacyApiKey, apiBaseUrl: legacyApiBaseUrl } = extractLegacyHeaders(req);

  console.log(`[${new Date().toISOString()}] POST ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionFingerprint(sessionId)}, Token: ${oauthToken ? tokenFingerprint(oauthToken) : 'none'}`);

  let transport: StreamableHTTPServerTransport;

  // Check if we have an existing session in memory (must be Streamable HTTP transport)
  const existingRuntime = sessionId ? sessionManager.getStreamableSession(sessionId) : null;

  // ROUTING HAPPENS BEFORE AUTHENTICATION, and that is deliberate — do not
  // "harden" it by moving the token check above this.
  //
  // A client whose session died needs the 404 whether or not its token is also
  // stale. Authenticate first and that client gets a 401 instead, sending it
  // through an OAuth round trip to fix a problem it does not have; if its token
  // is in fact fine, it re-authorizes, retries with the same dead session id
  // and lands right back here. The 404 is the answer to "your session is gone",
  // and it has to be reachable by a client that has nothing else wrong with it.
  //
  // Note for anyone auditing what is reachable unauthenticated: an existing
  // session is served without a token check too, so the Mcp-Session-Id is a
  // bearer credential in its own right, which is why the id is randomUUID()
  // and never derived from anything guessable.
  const isInitialize = isInitializeRequest(req.body);
  let route = routeForSessionRequest({
    hasRuntime: existingRuntime !== null,
    sessionId,
    isInitialize,
  });

  // The binding refuses USE of a session, never creation of one. Routing
  // prefers a session we hold, so a re-authorized client sending `initialize`
  // while its old session is still alive routes to 'use-existing'; its new
  // token does not match, and `initialize` is precisely the request that
  // repairs that, so without this it would be refused for as long as the stale
  // session lived. Fall through to 'create' rather than reusing the session: a
  // different credential may be a different user or project, so handing it the
  // old session's project binding would be worse than refusing.
  if (route === 'use-existing' && isInitialize && !credentialMatchesSession(req, sessionId)) {
    route = 'create';
  }

  if (route === 'use-existing') {
    // A session we hold, so the 404 is already decided above and untouched.
    if (refuseMismatchedCredential(req, res, sessionId)) return;

    transport = existingRuntime!.transport;
    console.log('[Streamable HTTP] Using existing transport for session:', sessionFingerprint(sessionId));
    sessionManager.touchSession(sessionId);
  } else if (route === 'not-found') {
    // A session id we do not hold: 404. A client that receives 404 for a request
    // carrying an Mcp-Session-Id MUST start a new session with an
    // InitializeRequest (Streamable HTTP, 2025-03-26), and the SDK's own server
    // answers the same way. A 400 is not the code the client's recovery is
    // keyed on: it reads as "your request was malformed", the client stops, and
    // every restart becomes a stuck client.
    //
    // Still unverified, and stated rather than implied: nobody has watched a
    // real editor take this 404 and re-initialize. The status is what the spec
    // and the SDK server agree on; the client's recovery is inferred from them.
    console.log('[Streamable HTTP] Unknown session, asking the client to start a new one:', sessionFingerprint(sessionId));
    return res.status(404).json({
      error: 'Session not found',
      error_description:
        'This session is not held by the server — it expired, or the server restarted. ' +
        'Send an initialize request to start a new one.',
    });
  } else if (route === 'create') {
    // New session - validate and create
    let projectInfo: ResolvedProject | null = null;
    if (oauthToken) {
      const resolution = await resolveProject(oauthToken);
      // A platform we could not reach is not a sign-in that has gone bad, so it
      // must not fall through to the challenge below.
      if (resolution.outcome === 'unavailable') return sendUnavailable(res);
      if (resolution.outcome === 'resolved') projectInfo = resolution.project;
    }

    if (!projectInfo) {
      if (!legacyApiKey && !oauthToken) {
        return sendUnauthorized(res, {
          error: 'authentication_required',
          error_description: 'Missing authentication. Provide Authorization: Bearer <OAUTH_TOKEN> or X-Api-Key header.',
          oauth_authorize_url: `${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.authorize}`,
        }, STREAMABLE_HTTP_ENDPOINTS.mcp);
      }

      if (oauthToken && !legacyApiBaseUrl) {
        return sendUnauthorized(res, {
          error: 'authorization_required',
          error_description: 'Your sign-in is no longer valid for this project — the platform refused it, or it expired. Authorize again. Complete the OAuth flow or call POST /api/projects/{projectId}/bind',
          oauth_authorize_url: `${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.authorize}`,
          projects_url: `${SERVER_CONFIG.publicUrl}${API_ENDPOINTS.projects}`,
        }, STREAMABLE_HTTP_ENDPOINTS.mcp);
      }

      if (!legacyApiBaseUrl) {
        return res.status(400).json({
          error: 'Missing X-Base-URL header (required for legacy authentication).',
        });
      }

      // At this point we have legacyApiBaseUrl but projectInfo is null
      // This means either:
      // 1. legacyApiKey is provided (valid legacy auth)
      // 2. oauthToken is provided but not bound to a project (invalid - already handled above)
      // 3. Both are provided (use legacyApiKey, ignore oauthToken)
      //
      // If we only have oauthToken without legacyApiKey, reject the request
      // because OAuth tokens are not interchangeable with API keys
      if (!legacyApiKey) {
        return sendUnauthorized(res, {
          error: 'invalid_credentials',
          error_description: 'Legacy authentication requires X-Api-Key header. OAuth tokens cannot be used as API keys.',
        }, STREAMABLE_HTTP_ENDPOINTS.mcp);
      }

      projectInfo = {
        apiKey: legacyApiKey,
        apiBaseUrl: legacyApiBaseUrl,
        projectId: 'legacy',
        projectName: 'Legacy Session',
        userId: 'legacy',
        organizationId: 'legacy',
        oauthTokenHash: 'legacy',
      };
    }

    // GENERATED, NEVER TAKEN FROM THE REQUEST. The binding exempts `initialize`
    // so a re-authorized client can recover, and that is only safe because the
    // id created here cannot be chosen by the caller: honouring an incoming
    // Mcp-Session-Id would let anyone with valid credentials initialize ONTO a
    // victim's session id and take it over. platform-paths.test.ts pins this.
    const newSessionId = randomUUID();

    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => newSessionId,
      onsessioninitialized: async (initializedSessionId) => {
        console.log(`[Streamable HTTP] Session initialized: ${sessionFingerprint(initializedSessionId)}`);
      },
    });

    try {
      await sessionManager.createSession(newSessionId, projectInfo, transport);
      console.log('[Streamable HTTP] New session created:', sessionFingerprint(newSessionId));

      const clientInfo = extractClientInfo(req.body);
      getAnalyticsService().trackSessionCreated({
        clientName: clientInfo?.name,
        clientVersion: clientInfo?.version,
        userAgent: req.headers['user-agent'] as string | undefined,
        transportType: 'streamable_http',
        projectId: projectInfo.projectId,
        userId: projectInfo.userId,
        organizationId: projectInfo.organizationId,
      });
    } catch (error) {
      console.error('[Streamable HTTP] Failed to create session:', error);
      return res.status(500).json({
        error: 'Failed to create session',
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  } else {
    return res.status(400).json({
      error: 'Session required. Send initialize request first or provide valid Mcp-Session-Id header.',
    });
  }

  console.log('[Streamable HTTP] Handling request...');
  await transport.handleRequest(req, res, req.body);
  console.log('[Streamable HTTP] Request handled');
});

/**
 * GET /mcp - Establish SSE stream for server-to-client notifications
 */
app.get(STREAMABLE_HTTP_ENDPOINTS.mcp, async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const authHeader = req.headers['authorization'] as string;
  const sessionManager = getSessionManager();

  console.log(`[${new Date().toISOString()}] GET ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionFingerprint(sessionId)}, Auth: ${authHeader ? 'present' : 'missing'}`);

  if (!sessionId) {
    return res.status(400).json({
      error: 'Missing Mcp-Session-Id header.',
    });
  }

  const runtime = sessionManager.getStreamableSession(sessionId);
  if (!runtime) {
    // A session this process does not hold does not exist anywhere.
    return res.status(404).json({
      error: 'Session not found. Initialize first with POST request.',
    });
  }

  // The stream is the quietest way to use a stolen id — it opens on the id
  // alone and then just receives. Bound here, after the 404 above.
  if (refuseMismatchedCredential(req, res, sessionId)) return;

  // This stream is the only sign of life for a client that opens it and then
  // sends nothing. Hold the session for as long as it is open, and start the
  // idle clock now rather than from whenever the last POST arrived.
  sessionManager.openStream(sessionId);
  res.on('close', () => sessionManager.closeStream(sessionId));
  sessionManager.touchSession(sessionId);

  await runtime.transport.handleRequest(req, res, req.body);
});

/**
 * DELETE /mcp - Close session
 */
app.delete(STREAMABLE_HTTP_ENDPOINTS.mcp, async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const sessionManager = getSessionManager();

  console.log(`[${new Date().toISOString()}] DELETE ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionFingerprint(sessionId)}`);

  if (!sessionId) {
    return res.status(400).json({
      error: 'Missing Mcp-Session-Id header.',
    });
  }

  const runtime = sessionManager.getStreamableSession(sessionId);
  if (!runtime) {
    // Likewise: there is no record to delete separately from the session.
    return res.status(404).json({
      error: 'Session not found.',
    });
  }

  // Destroying someone else's session is a one-request denial of service on
  // the id alone. Bound here, after the 404 above.
  if (refuseMismatchedCredential(req, res, sessionId)) return;

  try {
    await runtime.transport.handleRequest(req, res, req.body);
  } finally {
    // Always clean up the session, even if handleRequest throws
    await sessionManager.deleteSession(sessionId);
    console.log(`[Streamable HTTP] Session ${sessionFingerprint(sessionId)} closed`);
  }
});

// ============================================================================
// Legacy SSE Transport (Protocol version 2024-11-05) - DEPRECATED
// For backwards compatibility with older MCP clients
// ============================================================================

// Store SSE transports by session ID (separate from Streamable HTTP transports)
const sseTransports: Map<string, SSEServerTransport> = new Map();

/**
 * GET /sse - Establish Server-Sent Events stream
 * Used by older MCP clients with "type": "sse" configuration
 */
app.get(SSE_ENDPOINTS.sse, async (req: Request, res: Response) => {
  console.log(`[${new Date().toISOString()}] GET ${SSE_ENDPOINTS.sse} - Establishing SSE connection (DEPRECATED protocol)`);

  const oauthToken = extractOAuthToken(req);
  const { apiKey: legacyApiKey, apiBaseUrl: legacyApiBaseUrl } = extractLegacyHeaders(req);

  // Resolve project info
  let projectInfo: ResolvedProject | null = null;
  if (oauthToken) {
    const resolution = await resolveProject(oauthToken);
    if (resolution.outcome === 'unavailable') return sendUnavailable(res);
    if (resolution.outcome === 'resolved') projectInfo = resolution.project;
  }

  if (!projectInfo) {
    if (!legacyApiKey && !oauthToken) {
      return sendUnauthorized(res, {
        error: 'authentication_required',
        error_description: 'Missing authentication. Provide Authorization: Bearer <OAUTH_TOKEN> or X-Api-Key header.',
      }, SSE_ENDPOINTS.sse);
    }

    if (oauthToken && !legacyApiBaseUrl) {
      return sendUnauthorized(res, {
        error: 'authorization_required',
        error_description: 'Your sign-in is no longer valid for this project — the platform refused it, or it expired. Authorize again. Complete the OAuth flow.',
      }, SSE_ENDPOINTS.sse);
    }

    if (!legacyApiBaseUrl || !legacyApiKey) {
      return res.status(400).json({
        error: 'Missing X-Api-Key or X-Base-URL header (required for legacy authentication).',
      });
    }

    projectInfo = {
      apiKey: legacyApiKey,
      apiBaseUrl: legacyApiBaseUrl,
      projectId: 'legacy',
      projectName: 'Legacy Project',
      userId: 'unknown',
      organizationId: 'unknown',
      oauthTokenHash: '',
    };
  }

  // At this point projectInfo is guaranteed to be non-null
  const validProjectInfo = projectInfo;

  // Create SSE transport - it sends messages to /messages endpoint
  const transport = new SSEServerTransport(SSE_ENDPOINTS.messages, res);
  sseTransports.set(transport.sessionId, transport);

  console.log(`[SSE] Session created: ${sessionFingerprint(transport.sessionId)}, Project: ${validProjectInfo.projectName}`);

  // An idle SSE stream carries no bytes, so the load balancer closes it on its
  // idle timeout and the client sees the connection drop. A comment frame is
  // ignored by the event-stream parser and by the transport's own framing, so
  // it keeps the connection warm without being visible to the client.
  const keepAlive = setInterval(() => {
    if (res.writableEnded) return;
    try {
      res.write(': keepalive\n\n');
    } catch (error) {
      console.error(`[SSE] Keepalive write failed for ${sessionFingerprint(transport.sessionId)}:`, error);
    }
  }, SSE_KEEPALIVE_MS);
  keepAlive.unref();

  // Clean up on close
  res.on('close', () => {
    console.log(`[SSE] Session closed: ${sessionFingerprint(transport.sessionId)}`);
    clearInterval(keepAlive);
    sseTransports.delete(transport.sessionId);

    // Clean up the session from SessionManager (async with error handling)
    const sessionManager = getSessionManager();
    sessionManager.deleteSession(transport.sessionId).catch((error) => {
      console.error(`[SSE] Failed to cleanup session ${sessionFingerprint(transport.sessionId)}:`, error);
    });
  });

  // Create and connect MCP server
  const sessionManager = getSessionManager();
  try {
    await sessionManager.createSSESession(transport.sessionId, {
      apiKey: validProjectInfo.apiKey,
      apiBaseUrl: validProjectInfo.apiBaseUrl,
      projectId: validProjectInfo.projectId,
      projectName: validProjectInfo.projectName,
      userId: validProjectInfo.userId,
      organizationId: validProjectInfo.organizationId,
      oauthTokenHash: validProjectInfo.oauthTokenHash,
    }, transport);

    console.log(`[SSE] MCP server connected for session: ${sessionFingerprint(transport.sessionId)}`);

    getAnalyticsService().trackSessionCreated({
      clientName: undefined, // SSE: clientInfo not available until initialize message
      clientVersion: undefined,
      userAgent: req.headers['user-agent'] as string | undefined,
      transportType: 'sse',
      projectId: validProjectInfo.projectId,
      userId: validProjectInfo.userId,
      organizationId: validProjectInfo.organizationId,
    });
  } catch (error) {
    console.error(`[SSE] Failed to create session ${sessionFingerprint(transport.sessionId)}:`, error);

    // Clean up: remove transport from registry
    sseTransports.delete(transport.sessionId);

    // Attempt to close the transport gracefully
    try {
      await transport.close();
    } catch (closeError) {
      console.error(`[SSE] Error closing transport ${sessionFingerprint(transport.sessionId)}:`, closeError);
    }

    // Attempt to delete any partially created session (ignore errors if it wasn't created)
    sessionManager.deleteSession(transport.sessionId).catch(() => {
      // Session may not have been persisted yet, ignore error
    });

    // End the response if still open
    if (!res.headersSent) {
      res.status(500).json({
        error: 'session_creation_failed',
        error_description: error instanceof Error ? error.message : 'Failed to create MCP session',
      });
    } else {
      // Headers already sent (SSE started), just end the connection
      res.end();
    }
  }
});

/**
 * POST /messages - Receive messages from SSE clients
 */
app.post(SSE_ENDPOINTS.messages, async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;

  console.log(`[${new Date().toISOString()}] POST ${SSE_ENDPOINTS.messages} - Session: ${sessionFingerprint(sessionId)}`);

  if (!sessionId) {
    return res.status(400).json({
      error: 'Missing sessionId query parameter',
    });
  }

  const transport = sseTransports.get(sessionId);
  if (!transport) {
    return res.status(404).json({
      error: `Session not found. Establish SSE connection first via GET ${SSE_ENDPOINTS.sse}`,
    });
  }

  // The only thing that marks an SSE session alive; without it the session
  // reads as idle from creation however active the client is.
  getSessionManager().touchSession(sessionId);

  await transport.handlePostMessage(req, res, req.body);
});

// ============================================================================
// Server Startup
// ============================================================================

async function startServer() {
  try {
    // Validate configuration
    validateConfig();

    // This sweep IS session expiry: nothing else drops a session a client walked
    // away from, so a server that does not start it leaks every session it
    // creates (roughly 252 kB each) until the heap runs out.
    getSessionManager().startIdleSweep(SESSION_SWEEP_MS);

    const server = app.listen(SERVER_CONFIG.port, SERVER_CONFIG.host, () => {
      console.log(`
╔═══════════════════════════════════════════════════════════════════════╗
║              Insforge MCP Remote Server (OAuth)                       ║
╚═══════════════════════════════════════════════════════════════════════╝

🚀 Server: http://${SERVER_CONFIG.host}:${SERVER_CONFIG.port}

┌─────────────────────────────────────────────────────────────────────────
│ 📋 Streamable HTTP Transport (Protocol 2025-03-26) - RECOMMENDED
├─────────────────────────────────────────────────────────────────────────
│   POST/GET/DELETE ${SERVER_CONFIG.publicUrl}${STREAMABLE_HTTP_ENDPOINTS.mcp}
│
│   Client config:
│   {
│     "mcpServers": {
│       "insforge": {
│         "url": "${SERVER_CONFIG.publicUrl}${STREAMABLE_HTTP_ENDPOINTS.mcp}"
│       }
│     }
│   }
└─────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────────────────
│ 📋 Legacy SSE Transport (Protocol 2024-11-05) - DEPRECATED
├─────────────────────────────────────────────────────────────────────────
│   GET  ${SERVER_CONFIG.publicUrl}${SSE_ENDPOINTS.sse}       (establish SSE stream)
│   POST ${SERVER_CONFIG.publicUrl}${SSE_ENDPOINTS.messages}  (send messages)
│
│   Client config:
│   {
│     "mcpServers": {
│       "insforge": {
│         "type": "sse",
│         "url": "${SERVER_CONFIG.publicUrl}${SSE_ENDPOINTS.sse}"
│       }
│     }
│   }
└─────────────────────────────────────────────────────────────────────────

🔐 OAuth 2.0 Endpoints:
   • Discovery:  ${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.metadata}
   • Authorize:  ${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.authorize}
   • Token:      ${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.token}
   • Revoke:     ${SERVER_CONFIG.publicUrl}${OAUTH_ENDPOINTS.revoke}

🎯 Project API:
   • List:       GET  ${SERVER_CONFIG.publicUrl}${API_ENDPOINTS.projects}
   • Bind:       POST ${SERVER_CONFIG.publicUrl}${API_ENDPOINTS.bindProject}

💾 Configuration:
   • Sessions:   in this process only — a restart ends them
   • Insforge:   ${INSFORGE_CONFIG.apiBase}
   • Frontend:   ${INSFORGE_CONFIG.frontendUrl}
   • Analytics:  ${isAnalyticsConfigured() ? 'Mixpanel enabled' : 'Disabled (set MIXPANEL_TOKEN)'}
`);
    });

    const shutdown = async (signal: string) => {
      console.log(`\n🛑 Received ${signal}, shutting down...`);

      // Schedule forced exit timer FIRST to ensure we never hang
      const forceExitTimer = setTimeout(() => {
        console.error('⚠️ Forced shutdown after timeout');
        process.exit(1);
      }, 10000);

      try {
        // Close SSE transports
        console.log(`[Shutdown] Closing ${sseTransports.size} SSE connections...`);
        for (const [sessionId, transport] of sseTransports) {
          try {
            await transport.close();
          } catch (error) {
            console.error(`[Shutdown] Error closing SSE transport ${sessionFingerprint(sessionId)}:`, error);
          }
        }
        sseTransports.clear();

        // Close all MCP sessions
        try {
          const sessionManager = getSessionManager();
          sessionManager.stopIdleSweep();
          await sessionManager.closeAllSessions();
        } catch (error) {
          console.error('[Shutdown] Error closing sessions:', error);
        }

      } finally {
        // Always close the HTTP server, even if cleanup fails
        server.close(() => {
          clearTimeout(forceExitTimer);
          console.log('✅ Server shutdown complete');
          process.exit(0);
        });
      }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Start only when this module IS the process entry point, so importing it to
 * reach `app` (as the route tests do) does not bind the configured port.
 *
 * Compared through pathToFileURL because `import.meta.url` is a file: URL and
 * argv[1] is a path. And through realpathSync because npm installs the
 * `insforge-mcp-server` bin as a symlink, and Node resolves symlinks for
 * `import.meta.url` but not for argv[1]: without it the server silently does
 * not start when launched by its installed name.
 */
const entryPath = process.argv[1];
let isEntryPoint = false;
if (entryPath) {
  try {
    isEntryPoint = import.meta.url === pathToFileURL(realpathSync(entryPath)).href;
  } catch {
    // argv[1] naming something unresolvable is not a reason to refuse to boot.
    isEntryPoint = import.meta.url === pathToFileURL(entryPath).href;
  }
}

if (isEntryPoint) {
  startServer();
}
