import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import { randomUUID, createHash } from 'crypto';
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
 * Three outcomes, not two.
 *
 * `unavailable` is the one that had to be added back. #95 collapsed every
 * failure into "no project" so that a stale token could not produce a 500 with
 * no challenge, and the justification I wrote was that the client's available
 * action is identical either way. **It stops being identical the moment a retry
 * would have worked** — which is exactly a platform blip. Iris named that, and
 * she is right: the rule is 401 when the credential is the problem, 5xx when we
 * could not tell.
 *
 * Both halves still matter. Reporting a fault as 401 drags a user through a
 * browser login to fix something that would have cleared on its own; reporting
 * a dead credential as 500 tells the client to give up when signing in again is
 * exactly what it should do.
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
    // NOTHING here may escape as an unhandled throw — that is still the point
    // of this wrapper, and it is why a stale bearer no longer produces a 500
    // with a raw Express stack and no WWW-Authenticate (#95, measured on the
    // live slug).
    //
    // What has changed is WHICH answer it turns into. #95 made every failure a
    // challenge, on the argument that the client's available action is
    // identical either way. That argument is sound for a dead credential and
    // wrong for a platform blip: re-authorizing does not fix a platform that is
    // down, and telling a client its sign-in is invalid throws away a working
    // session and sends a person to a browser for nothing.
    //
    // A token that does not open never reaches here — resolveProjectFromToken
    // returns null for that, which is 'unauthorized'. Anything that throws is
    // by definition something we could not determine, so it is 'unavailable'
    // and the caller answers 503 with Retry-After. The challenge stays for the
    // case the challenge is actually the remedy.
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
 * ONE FUNCTION, CALLED BY EVERY VERB, and that is the whole point of its
 * existing at all. The first version of this bound POST only — and a session is
 * reachable by three verbs, so it was a POST-shaped fix for a session-shaped
 * problem. Quinn demonstrated the gap rather than argued it:
 *
 *   DELETE /mcp with just the session id      -> 200
 *   the victim's very next valid request      -> 404
 *
 * One request, no credential of any kind, and someone else is logged out. GET
 * is quieter and worse: it opens the server->client stream on the id alone and
 * receives everything pushed for that session, with no forged requests at all.
 *
 * Returns true when it has already answered, so a caller is one line:
 *
 *   if (refuseMismatchedCredential(req, res, sessionId)) return;
 *
 * Placement matters and is not interchangeable: call it only AFTER the handler
 * has established that this process holds the session. Before that, it would
 * authenticate ahead of routing and a client with a dead session plus a stale
 * token would get 401 where it needs the 404 that tells it to start over.
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

  // 404, NOT 401, and this is the one decision here I got wrong first.
  //
  // 401 is the instruction "re-run OAuth". Consider the client that just did:
  // it re-authorized, holds a NEW token, and retries with the session id it
  // still has. The credential is valid and the session is real — but they
  // belong to different sign-ins, so a 401 sends it round the OAuth loop again,
  // to arrive with another new token and the same old id. That is an infinite
  // loop triggered by the ordinary act of signing in again, and I only saw it
  // because I tested the re-authorize case rather than only the attacker.
  //
  // The action this client actually needs is the one the routing 404 already
  // gives: start a new session. So the answer is identical to "we do not hold
  // that session" — which it effectively is, for you — and the recovery is
  // coherent: ANY request naming a session this process will not serve you gets
  // 404 and initializes again.
  //
  // It also happens to leak less. To someone probing with a stolen id, "not
  // found" and "not yours" are now the same answer.
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
 * OAuth Dynamic Client Registration (RFC 7591)
 */
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

  // #104: the response used to echo `grant_types` and `response_types` straight
  // back, so a client that asked for `password` or a device code was TOLD YES at
  // registration and refused at the token endpoint. A registration response is
  // the server asserting what it will honour, and a client is entitled to plan
  // against it.
  //
  // Rejected here rather than narrowed silently, for the reason this file keeps
  // arriving at: refuse where the caller is listening. A client that asked for a
  // grant it needs should find out now, from a message naming what it can have,
  // rather than at the first token request in front of a user.
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

    // THE THIRD UPSTREAM CALL, and the one that renders in a person's browser.
    //
    // Iris forced the platform unroutable on a branch env and drove this path
    // without a login — /oauth/authorize is unauthenticated, so a stranger can
    // reach the exchange:
    //
    //   platform reachable    400 invalid_grant     (the platform's own answer)
    //   platform unroutable   500 "fetch failed"    Node's raw message, no Retry-After
    //
    // My own rule — 401 when the credential is the problem, 5xx when we could
    // not tell — held on revoke and resolve and not here, which is exactly the
    // shape that reads as done and is not. A mid-sign-in platform blip showed a
    // human `server_error: fetch failed` on the callback page.
    //
    // The two cases are now separated by WHERE they are handled: a thrown error
    // means we could not reach the platform and falls to the catch below, which
    // answers 503; a parsed body with an `error` field means the platform
    // answered and declined, which stays a 400.
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
          // Deliberately not the raw error. "fetch failed" is Node talking to
          // itself; it tells the person nothing and is what was reaching the
          // browser before.
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
    // The refresh token rides along from here. It arrived in this same response
    // and was dropped on the floor until now, which is the whole reason a
    // connected client died after an hour.
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
      const { accessToken, refreshToken } = await oauthManager.exchangeCode(
        code as string,
        redirect_uri as string,
        code_verifier as string | undefined
      );

      getAnalyticsService().trackOAuthSuccess({
        clientId: req.body.client_id || 'unknown',
        scope: 'mcp:read mcp:write',
      });

      // 24 hours, not the binding's 30 days: a value that cannot be revoked
      // directly should not live for a month. But the platform token sealed
      // inside has its own expiry, and whichever runs out first ends the
      // session — so advertise the real minimum rather than our ceiling.
      //
      // Saying a flat 24h was the "safe direction" only for us. For a client
      // whose platform token dies in two hours it means four more of retrying a
      // credential we already know is dead, instead of signing in again.
      const payload = readAccessToken(accessToken, accessTokenKey());
      const expiresIn = payload
        ? accessTokenLifetimeSeconds(payload)
        : ACCESS_TOKEN_TTL_SECONDS;

      // refresh_token is spread in rather than always present: a code minted
      // before this shipped carries none, and `refresh_token: undefined` would
      // serialise the key away anyway — but stating the conditional makes the
      // absence deliberate rather than incidental. Quinn caught this being
      // MINTED AND DROPPED one line above: exchangeCode returned it, the
      // destructure ignored it, and the response omitted it, so discovery
      // advertised a grant no client could ever obtain the credential for.
      // Nothing was type-wrong about discarding a returned field, which is why
      // only a real login found it.
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
    // Until now this answered `unsupported_grant_type`, which is why every
    // connected client died after an hour: the platform token sealed in our
    // access token is a ONE-HOUR JWT, we advertise whichever expiry is sooner,
    // and there was no way back except a browser. For a CLI that is an
    // annoyance; for a hosted connector signed in once in someone else's
    // browser it is a broken integration.
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

    // The platform declining OUR credentials is not the user's grant expiring,
    // and collapsing the two is the same mistake as answering "sign in again"
    // for an unreachable platform — one step further in.
    //
    //   {"error":"invalid_client","message":"Invalid client credentials"}  401
    //
    // is what it returns when INSFORGE_CLIENT_SECRET is wrong, which is exactly
    // what a botched rotation or a half-finished client swap produces. Reported
    // as invalid_grant it tells EVERY connected user to sign in again, they all
    // do, and every new sign-in fails the same way — a stampede caused by our
    // config and blamed on their session. Measured against the real platform
    // rather than assumed.
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

  // THIS ENDPOINT USED TO DO NOTHING, and returned 200 while doing it.
  //
  // With the binding row gone, all it did was drop the cached project key. The
  // sealed bearer still carried a live platform token, so the very next request
  // re-fetched the key and succeeded: revoking a leaked credential forced one
  // extra round trip and left it working for its full 24 hours. A revoke that
  // reports success and changes nothing is worse than no revoke at all, because
  // the person who called it stops looking for the leak.
  //
  // So revoke the thing that actually grants access — the platform token sealed
  // inside. Iris confirmed the upstream endpoint is deployed and needs only our
  // client id. The alternative considered and rejected was a local revocation
  // marker: that is a durable per-token record consulted on every request, which
  // is `mcp:auth:binding:` again under another name and would put back the store
  // this whole effort removed.
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
    // exist; it is not licence to report a revocation that failed as one that
    // worked. The caller is trying to shut off a credential — telling them it
    // is off when it is still live is the same false assurance this endpoint
    // just stopped giving, one layer down.
    //
    // This does mean a failure here distinguishes "was ours" from "was not",
    // which the blanket 200 exists to hide. It only happens when the platform
    // is already failing, it is not attacker-triggerable, and the alternative
    // is lying about a security operation. Stated so the trade is visible
    // rather than discovered.
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

  // UNSEAL FIRST. This handed our own bearer straight to the platform, which
  // worked only while the bearer WAS a platform token. Since the token became a
  // sealed envelope, the platform receives a string it has never issued and
  // answers 401 — so `/api/projects` has been broken for every caller, and with
  // it `list-projects`, the capability this whole design exists to enable.
  //
  // The bug is the shape the sealed token invites: every place that used to
  // forward the bearer now has to open it and forward what is INSIDE. This was
  // the last one, and it was missed because nothing calls this endpoint in
  // tests — the project-selection page is its only real caller.
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
  // bearer credential in its own right. That is unchanged by this file's
  // history — master does the same — and it is why the id is randomUUID() and
  // never derived from anything guessable.
  const isInitialize = isInitializeRequest(req.body);
  let route = routeForSessionRequest({
    hasRuntime: existingRuntime !== null,
    sessionId,
    isInitialize,
  });

  // THE BINDING REFUSES USE OF A SESSION, NEVER CREATION OF ONE, and this line
  // is here because the first version got that wrong in a way tests missed.
  //
  // Routing prefers a session we hold, so a re-authorized client sending
  // `initialize` while its OLD session is still alive routes to 'use-existing'.
  // Its new token does not match, so it was refused — and `initialize` is
  // precisely the request that repairs the situation, so it was refused
  // forever, for as long as the stale session lived. A loop with a 24-hour
  // exit, caused by signing in again.
  //
  // My test for the escape hatch asserted `hasRuntime: false` and passed
  // happily while the live-session case failed. It only showed up by driving a
  // real re-authorization end to end.
  //
  // Falling through to 'create' rather than reusing the session is the correct
  // half too: a different credential may be a different user or project, so
  // handing it the old session's project binding would be worse than refusing.
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
    // A session id we do not hold. 404 IS THE ANSWER, and it is the one part of
    // this change a client actually depends on.
    //
    // The restore branch that used to be here rebuilt a server and transport
    // from a Redis record around the same session id. With no record there is
    // nothing to rebuild, so the question is only which status says so, and the
    // protocol answers it: a client that receives 404 for a request carrying an
    // Mcp-Session-Id MUST start a new session with an InitializeRequest
    // (Streamable HTTP, 2025-03-26). The SDK's own server does the same —
    // "Requests with invalid session IDs are rejected with 404 Not Found".
    //
    // The 400 this used to fall through to is the wrong shape for the same
    // reason a 500 was wrong for a stale token (#95): it is not the code the
    // client's recovery is keyed on, so it reads as "your request was
    // malformed" and the client stops instead of signing back in. Answering 400
    // here would turn every restart into a stuck client.
    //
    // NOT verified end to end: nobody has watched a real editor take this 404
    // and re-initialize. The status is what the spec and the SDK server agree
    // on; the client's behaviour is Quinn's test, and it is the acceptance for
    // this change rather than a detail after it.
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

    // GENERATED, NEVER TAKEN FROM THE REQUEST — and since the binding landed
    // this line is load-bearing rather than incidental.
    //
    // The binding exempts `initialize` so a re-authorized client can recover.
    // That exemption is only safe because the id created here cannot be chosen
    // by the caller. If this ever honoured an incoming Mcp-Session-Id — to
    // "preserve session ids across re-initialization", say — an attacker with
    // their own perfectly valid credentials could initialize ONTO a victim's
    // session id, overwrite the entry in the session map, and take the session
    // over. The exemption would then hand them the exact thing the binding
    // exists to prevent.
    //
    // Quinn went looking for that hole specifically and measured it closed:
    // asked for 11111111-…, got a server-generated id, header ignored. There is
    // a test pinning it, because "we happen to generate it" is not a property
    // anyone would notice losing.
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
    // The "exists but not active" branch is gone with the store that made it
    // possible: a session this process does not hold does not exist anywhere.
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

  // The streamable path stamps a session on every request; the SSE path did
  // not, so an SSE session read as idle from creation however active the client
  // was. Kept — it is still the only thing that marks an SSE session alive.
  // It can no longer fail, so it no longer needs a catch.
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

    // Unconditional, where it used to be gated on Redis being configured.
    //
    // That gate was right when Redis owned session lifetime and this timer only
    // reclaimed the instances left behind. Now this IS session expiry: nothing
    // else drops a session that a client walked away from, so a server that
    // does not start the sweep leaks every session it ever creates until the
    // heap runs out. Roughly 252 kB per session against this machine's ~493 MB
    // heap limit — about 2,000 — so "leaks" means hours, not months.
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

startServer();
