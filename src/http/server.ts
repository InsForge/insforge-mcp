import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import { randomUUID, createHash } from 'crypto';
import v8 from 'node:v8';

// Transport imports
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

// Local imports
import { getSessionManager } from './session-manager.js';
import { getRedisClient, closeRedisClient, getRedisConfig, isRedisConfigured } from './redis.js';
import { getOAuthManager } from './oauth-manager.js';
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
import { sendOAuthError } from './oauth-error-response.js';
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
import { ACCESS_TOKEN_TTL_SECONDS, readAccessToken } from './access-token.js';
import { getProjectKeyCache } from './project-key-cache.js';
import { accessTokenKey } from './config.js';
import { statusForHttpError } from './error-status.js';
import { PACKAGE_VERSION } from '../shared/version.js';

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();

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
 * Resolve project information from OAuth token
 */
async function resolveProjectFromToken(token: string): Promise<{
  apiKey: string;
  apiBaseUrl: string;
  projectId: string;
  projectName: string;
  userId: string;
  organizationId: string;
  oauthTokenHash: string;
} | null> {
  const oauthManager = getOAuthManager();
  try {
    return await oauthManager.resolveProjectFromToken(token);
  } catch (error) {
    // NOTHING here may escape, and that is the whole point of this wrapper.
    //
    // Measured on the live slug: a stale bearer — one issued before today's
    // token format changed — reached Redis, threw MaxRetriesPerRequestError,
    // and Express answered with a 500 and a raw stack. No WWW-Authenticate.
    //
    // "Not a 500" is not the same as "a 401". The challenge header is the ONLY
    // thing that tells an MCP client to re-run OAuth; a 500 reads as "the
    // server is broken, give up", so a client holding an old token never
    // recovers on its own. Iris found this, and it is not hypothetical: the
    // token format changed three times today and every client holding an
    // earlier one lands here, as will every existing user at the cutover.
    //
    // The honest cost, stated rather than hidden: a genuine infrastructure
    // fault is now also reported as an authorization failure, which
    // mislabels it. That is the right trade only because the client's
    // available action is identical either way — re-authorize — and because a
    // silent 500 gives it no action at all. The fault is logged at error level
    // so it stays visible to us even though the client is told something
    // softer.
    console.error('[OAuth] Could not resolve a token; answering with a challenge:', error);
    return null;
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
 * Extract legacy headers for backwards compatibility
 */
function extractLegacyHeaders(req: Request): { apiKey?: string; apiBaseUrl?: string } {
  return {
    apiKey: req.headers['x-api-key'] as string,
    apiBaseUrl: req.headers['x-base-url'] as string,
  };
}

/**
 * Heap numbers for the health payload.
 *
 * The session leak had to be diagnosed by counting objects and multiplying by
 * a separately-measured size, because the process publishes no memory metric
 * at all — so "how long until it dies" could only ever be an estimate. V8's
 * own limit is the number that actually decides that, and exposing it costs
 * nothing.
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

app.get(API_ENDPOINTS.health, async (_req: Request, res: Response) => {
  const sessionManager = getSessionManager();
  const stats = await sessionManager.getStats();

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

  // The registration is carried by the id itself, so nothing is written here.
  // mintClientId validates redirect_uris — count, absoluteness, scheme, and
  // loopback-only plaintext http — and rejects anything it would not be able to
  // read back, which is why this route no longer pre-checks the array itself.
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
    // Refused HERE, not at the end.
    //
    // #91 made authorization codes stateless, which means they cannot be
    // single-use, which means PKCE is what stops a replay. I put the refusal in
    // createAuthorizationCode — and measured on the slug that a client without
    // PKCE still gets a 302, signs in through the browser, picks a project, and
    // only THEN fails. The person did all the work before we told them we were
    // never going to accept it.
    //
    // That is the same mistake as validating a redirect_uri at authorize
    // instead of at registration: reject where the caller is listening, not
    // where only a browser can see it. The MCP client reads this response; it
    // never reads the one at the end of the flow.
    return sendOAuthError(req, res, 400, {
      error: 'invalid_request',
      error_description:
        'code_challenge is required. This server advertises S256 as its only ' +
        'code_challenge_method and issues authorization codes that carry their own state, ' +
        'so PKCE is what makes a code safe to accept.',
    });
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
    // Nothing here can recover automatically. The MCP SDK only re-registers on
    // an invalid_client from the token endpoint or from registration, and it
    // never sees this response — the browser does. So the person holding the
    // tab is the only one who can act, and they need to be told how.
    //
    // This is also the path every client registered before this change takes:
    // its id names a Redis row that is no longer read. The page below is the
    // correct answer for them too — re-register and it works.
    console.log('[OAuth] Client id at authorize did not verify');
    return sendOAuthError(req, res, 400, {
      error: 'invalid_client',
      error_description: 'Unknown client_id. Register client first via /oauth/register.',
    });
  }

  // Exact match against what the client registered, per RFC 6749 §3.1.2.3.
  // This is the check mcp-use's oauthProxy omits, and omitting it is
  // authorization-code theft: the code would be delivered to whatever URI the
  // request named.
  if (!isRegisteredRedirectUri(registration, redirect_uri)) {
    // The branch a real user is most likely to reach, and until now the one
    // that told them least: raw JSON in a browser tab.
    return sendOAuthError(req, res, 400, {
      error: 'invalid_request',
      error_description: 'redirect_uri does not match any registered redirect URIs for this client.',
    });
  }

  // No TTL to refresh: the registration is not stored, so it cannot expire.
  // The 30-day idle timeout this replaces is the bug that silently broke every
  // client 30 days after it was installed.

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
    // john-bot's Critical on this PR, and it is the tenth consumer in a change
    // whose whole point was not stopping at the ones I noticed. The entire GET
    // is a browser navigation, so a throw anywhere inside it — a platform
    // outage, a missing signing key — put raw JSON in the person's tab.
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
    // user's tab. The callback is ALWAYS a browser navigation — it is the
    // platform redirecting them here — so JSON was never right on any branch.
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
    const tokenResponse = await fetch(`${INSFORGE_CONFIG.apiBase}/api/oauth/v1/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: OAUTH_CONFIG.callbackUrl,
        client_id: INSFORGE_CONFIG.clientId,
        client_secret: INSFORGE_CONFIG.clientSecret,
        code_verifier: authState.insforgeCodeVerifier,
      }),
    });

    const tokens = await tokenResponse.json() as {
      access_token?: string;
      refresh_token?: string;
      token_type?: string;
      expires_in?: number;
      error?: string;
      error_description?: string;
    };

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

    // The token rides inside the state instead of a row keyed by it. The
    // state_id therefore CHANGES here — it is the record, so a record with one
    // more field is a different string.
    const stateWithToken = oauthManager.attachPlatformToken(authState, tokens.access_token);

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
    // The EIGHTH browser-reachable branch, and the third time on this PR that
    // I converted the ones I could see and missed one. The callback is a
    // browser navigation end to end, so its outer catch is as visible as any
    // branch inside it. Counting is not the method; routing everything through
    // one helper is, and this is the last place that was not.
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
      const { accessToken } = await oauthManager.exchangeCode(
        code as string,
        redirect_uri as string,
        code_verifier as string | undefined
      );

      getAnalyticsService().trackOAuthSuccess({
        clientId: req.body.client_id || 'unknown',
        scope: 'mcp:read mcp:write',
      });

      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        // 24 hours, not the binding's 30 days. A value that cannot be revoked
        // directly should not live for a month, and the platform token sealed
        // inside has its own expiry — whichever runs out first ends the
        // session, which is the safe direction.
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
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
    getAnalyticsService().trackOAuthFailure({
      errorType: 'unsupported_grant_type',
      errorDescription: 'Refresh tokens are not supported',
      endpoint: '/oauth/token',
    });
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Refresh tokens are not supported',
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

  // There is no row to delete any more: the token carries its own record. What
  // we CAN do is drop the cached project key, so the very next call re-asks the
  // platform instead of using a key we already fetched — and the platform is
  // where revocation is actually enforced (validateAccessToken checks
  // `revoked` on every call).
  //
  // RFC 7009 §2.2 wants 200 whatever happens, including for a token we do not
  // recognise, so that this endpoint cannot be used to probe which tokens are
  // real. That was already the behaviour and it stays.
  try {
    const payload = readAccessToken(token as string, accessTokenKey());
    if (payload) {
      getProjectKeyCache().forgetUser(payload.userId);
      console.log(`[OAuth] Cached project keys dropped for ${payload.userId} on revoke`);
    }
  } catch {
    // Deliberately swallowed: see above.
  }
  res.status(200).send();
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

  try {
    const oauthManager = getOAuthManager();
    const projects = await oauthManager.getAvailableProjects(token);
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

  // A token can no longer be re-pointed at another project, because there is no
  // row to update — the project is sealed inside the token the client already
  // holds. Saying so is better than the alternatives: silently doing nothing
  // would look like success, and issuing a NEW token here would hand a caller a
  // credential through an endpoint that never authenticated anyone.
  try {
    const payload = readAccessToken(token, accessTokenKey());
    if (!payload) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    if (payload.projectId === projectId) {
      // Already there. Idempotent rather than an error: a client retrying is
      // not making a mistake.
      //
      // The id and nothing else. This used to echo the project's name and
      // organization out of the token, and those two fields are exactly what
      // made the sealed payload unbounded — a project name has no maximum
      // length upstream. They are display data, so they left the credential
      // (access-token.ts) rather than staying in it to serve one response body.
      //
      // Re-fetching them here to keep the shape was the tempting move and the
      // wrong one: it would put a platform round-trip, and a platform outage,
      // in the path of an endpoint that answers purely from the token today.
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

  console.log(`[${new Date().toISOString()}] POST ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionId || 'none'}, Token: ${oauthToken ? tokenFingerprint(oauthToken) : 'none'}`);

  let transport: StreamableHTTPServerTransport;

  // Check if we have an existing session in memory (must be Streamable HTTP transport)
  const existingRuntime = sessionId ? sessionManager.getStreamableSession(sessionId) : null;

  if (existingRuntime) {
    transport = existingRuntime.transport;
    console.log('[Streamable HTTP] Using existing transport for session:', sessionId);
    await sessionManager.touchSession(sessionId);
  } else if (sessionId && await sessionManager.hasSession(sessionId)) {
    console.log('[Streamable HTTP] Session found in Redis, restoring:', sessionId);

    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => sessionId,
      onsessioninitialized: () => {
        console.log(`[Streamable HTTP] Session restored: ${sessionId}`);
      },
    });

    const server = await sessionManager.restoreSession(sessionId, transport);
    if (!server) {
      return res.status(500).json({
        error: 'Failed to restore session from Redis',
      });
    }
  } else if (isInitializeRequest(req.body)) {
    // New session - validate and create
    let projectInfo = oauthToken ? await resolveProjectFromToken(oauthToken) : null;

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

    const newSessionId = randomUUID();

    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => newSessionId,
      onsessioninitialized: async (initializedSessionId) => {
        console.log(`[Streamable HTTP] Session initialized: ${initializedSessionId}`);
      },
    });

    try {
      await sessionManager.createSession(newSessionId, projectInfo, transport);
      console.log('[Streamable HTTP] New session created:', newSessionId);

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

  console.log(`[${new Date().toISOString()}] GET ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionId || 'none'}, Auth: ${authHeader ? 'present' : 'missing'}`);

  if (!sessionId) {
    return res.status(400).json({
      error: 'Missing Mcp-Session-Id header.',
    });
  }

  const runtime = sessionManager.getStreamableSession(sessionId);
  if (!runtime) {
    if (await sessionManager.hasSession(sessionId)) {
      return res.status(400).json({
        error: 'Session exists but not active. Send a POST request to restore the session first.',
      });
    }
    return res.status(404).json({
      error: 'Session not found. Initialize first with POST request.',
    });
  }

  // This stream is the only sign of life for a client that opens it and then
  // sends nothing. Hold the session for as long as it is open, and restart the
  // Redis record's clock now so a restart can still restore the session.
  sessionManager.openStream(sessionId);
  res.on('close', () => sessionManager.closeStream(sessionId));
  await sessionManager.touchSession(sessionId);

  await runtime.transport.handleRequest(req, res, req.body);
});

/**
 * DELETE /mcp - Close session
 */
app.delete(STREAMABLE_HTTP_ENDPOINTS.mcp, async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const sessionManager = getSessionManager();

  console.log(`[${new Date().toISOString()}] DELETE ${STREAMABLE_HTTP_ENDPOINTS.mcp} - Session: ${sessionId || 'none'}`);

  if (!sessionId) {
    return res.status(400).json({
      error: 'Missing Mcp-Session-Id header.',
    });
  }

  const runtime = sessionManager.getStreamableSession(sessionId);
  if (!runtime) {
    if (await sessionManager.hasSession(sessionId)) {
      await sessionManager.deleteSession(sessionId);
      return res.status(200).json({
        message: 'Session deleted from storage.',
      });
    }
    return res.status(404).json({
      error: 'Session not found.',
    });
  }

  try {
    await runtime.transport.handleRequest(req, res, req.body);
  } finally {
    // Always clean up the session, even if handleRequest throws
    await sessionManager.deleteSession(sessionId);
    console.log(`[Streamable HTTP] Session ${sessionId} closed`);
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
  let projectInfo = oauthToken ? await resolveProjectFromToken(oauthToken) : null;

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

  console.log(`[SSE] Session created: ${transport.sessionId}, Project: ${validProjectInfo.projectName}`);

  // An idle SSE stream carries no bytes, so the load balancer closes it on its
  // idle timeout and the client sees the connection drop. A comment frame is
  // ignored by the event-stream parser and by the transport's own framing, so
  // it keeps the connection warm without being visible to the client.
  const keepAlive = setInterval(() => {
    if (res.writableEnded) return;
    try {
      res.write(': keepalive\n\n');
    } catch (error) {
      console.error(`[SSE] Keepalive write failed for ${transport.sessionId}:`, error);
    }
  }, SSE_KEEPALIVE_MS);
  keepAlive.unref();

  // Clean up on close
  res.on('close', () => {
    console.log(`[SSE] Session closed: ${transport.sessionId}`);
    clearInterval(keepAlive);
    sseTransports.delete(transport.sessionId);

    // Clean up the session from SessionManager (async with error handling)
    const sessionManager = getSessionManager();
    sessionManager.deleteSession(transport.sessionId).catch((error) => {
      console.error(`[SSE] Failed to cleanup session ${transport.sessionId}:`, error);
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

    console.log(`[SSE] MCP server connected for session: ${transport.sessionId}`);

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
    console.error(`[SSE] Failed to create session ${transport.sessionId}:`, error);

    // Clean up: remove transport from registry
    sseTransports.delete(transport.sessionId);

    // Attempt to close the transport gracefully
    try {
      await transport.close();
    } catch (closeError) {
      console.error(`[SSE] Error closing transport ${transport.sessionId}:`, closeError);
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

  console.log(`[${new Date().toISOString()}] POST ${SSE_ENDPOINTS.messages} - Session: ${sessionId || 'none'}`);

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

  // Streamable HTTP refreshes the Redis record on every request; the SSE path
  // did not, so an SSE record lapsed 24h after creation however active the
  // client was, and /health under-reported live SSE sessions. Fire-and-forget:
  // a failed refresh must not fail the message.
  getSessionManager()
    .touchSession(sessionId)
    .catch((error) => {
      console.error(`[SSE] Failed to refresh session ${tokenFingerprint(sessionId)}`, error);
    });

  await transport.handlePostMessage(req, res, req.body);
});

// ============================================================================
// Server Startup
// ============================================================================

async function startServer() {
  try {
    // Validate configuration
    validateConfig();

    // Redis is on its way out of this server, and until the last use is gone a
    // deploy without it should still boot. It used to exit 1 here, before
    // app.listen, so nothing was reachable — not /health, not discovery, not
    // even a log line naming the cause once the container had looped a few
    // times. A server that answers and refuses to sign anyone in is far more
    // diagnosable than one that is not there.
    if (isRedisConfigured()) {
      const redis = getRedisClient();
      await redis.ping();
      console.log('[Redis] Connection verified');

      // Runtime sessions are only dropped on an explicit DELETE, which
      // Streamable HTTP clients rarely send. Reap the ones Redis has already
      // expired. Nothing to sweep when there is no Redis to expire them.
      getSessionManager().startIdleSweep(SESSION_SWEEP_MS);
    } else {
      // Measured rather than assumed: with no Redis, /health and all four
      // discovery documents answer 200 and POST /mcp gives its 401 challenge,
      // which is everything needed to prove the edge routes us. /oauth/* still
      // 500s — registration and auth state are the next slices — so the list
      // below says so instead of promising a login that will not complete.
      console.warn(
        '[Redis] Not configured (no REDIS_URL or REDIS_HOST). ' +
          'The whole OAuth path now runs without it — registration, sign-in, ' +
          'tokens. Only MCP SESSIONS still need Redis; /mcp and /sse will fail ' +
          'until those move in-process.'
      );
    }

    const server = app.listen(SERVER_CONFIG.port, SERVER_CONFIG.host, () => {
      const redisConfig = getRedisConfig();
      // The banner used to print "localhost:6379" whether or not anything was
      // there, which is the same shape of lie as the REDIS_PASSWORD that looked
      // configured and never reached ioredis. Print what is true.
      const redisLine = isRedisConfigured()
        ? `${redisConfig.host}:${redisConfig.port} (TLS: ${redisConfig.tls}, Cluster: ${redisConfig.cluster})`
        : 'not configured — OAuth works; MCP sessions unavailable';
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
   • Redis:      ${redisLine}
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
            console.error(`[Shutdown] Error closing SSE transport ${sessionId}:`, error);
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

        // Close Redis connection
        try {
          await closeRedisClient();
        } catch (error) {
          console.error('[Shutdown] Error closing Redis client:', error);
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

startServer();
