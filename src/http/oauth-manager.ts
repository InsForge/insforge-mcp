import { createHash, randomBytes } from 'crypto';
import { sealAuthState, openAuthState, InvalidAuthStateError } from './auth-state.js';
import { issueAccessToken, readAccessToken } from './access-token.js';
import { issueRefreshToken } from './refresh-token.js';
import { getProjectKeyCache } from './project-key-cache.js';
import { newStateHandle } from './auth-state-cookie.js';
import { authStateKey, authCodeKey, accessTokenKey, refreshTokenKey } from './config.js';
import { isAuthorizationRefusal } from './error-status.js';
import {
  validateToken,
  getProjectAccess,
  getAllUserProjects,
  type ProjectAccess,
  type Organization,
  type Project,
  InsforgeApiError,
} from './insforge-api.js';

// ============================================================================
// PKCE Helpers
// ============================================================================

/**
 * Generate a random code verifier for PKCE
 */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Generate code challenge from verifier (SHA256)
 */
export function generateCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Generate random state for CSRF protection
 */
export function generateState(): string {
  return randomBytes(16).toString('hex');
}

/**
 * OAuth authorization state, sealed into a cookie rather than stored
 * Used during the OAuth flow before token exchange
 *
 * This stores both:
 * 1. The MCP client's original request parameters
 * 2. The PKCE verifier we generate when calling Insforge OAuth
 */
interface AuthorizationState {
  /**
   * Ties the sealed cookie to the `state` parameter the platform echoes back.
   * The callback requires them to match; without that the cookie alone would
   * authorise any callback that arrived carrying one.
   */
  handle: string;

  // Original MCP client request.
  //
  // clientId is deliberately NOT here. Nothing read it after authorize, and it
  // is the largest field by far — a signed client id is ~171 characters and may
  // be up to 4096, which is what pushed the sealed envelope past a 4096-byte
  // cookie.
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;  // From MCP client (if using PKCE)
  codeChallengeMethod?: string;

  // Our PKCE verifier for calling Insforge OAuth
  insforgeCodeVerifier: string;

  /**
   * The platform access token, present only AFTER the callback has exchanged
   * the code for it.
   *
   * It used to live in its own Redis row (mcp:oauth:token:<state>) read twice
   * by the project-selection page. Folding it into the state it was already
   * keyed by removes the row and the second lookup — and it is safe here for
   * exactly one reason: this envelope is encrypted, not signed. A bearer token
   * in a signed-but-readable blob would be a bearer token in a URL.
   */
  platformAccessToken?: string;

  /**
   * The platform REFRESH token, from the same exchange.
   *
   * Read into a response type and dropped, until now — which is why every
   * connected client dies after an hour: the token beside this one is a
   * one-hour JWT and nothing existed to renew it. Safe here for the same reason
   * as its neighbour, and it needs that reason more: this envelope is
   * encrypted, and this is the longer-lived of the two credentials by thirty
   * days to one hour.
   */
  platformRefreshToken?: string;

  createdAt: number;
}


// TTLs
const AUTH_CODE_TTL = 5 * 60; // 5 minutes

/**
 * Generate a hash of the token for storage
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Generate a random code
 */
function generateCode(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * OAuthManager handles the OAuth authorization flow and token-to-project binding
 */
export class OAuthManager {
  /**
   * Re-seal an existing state with the platform token attached.
   *
   * Returns a NEW state_id: the sealed value IS the record, so adding a field
   * necessarily produces a different string. The expiry restarts here, which
   * matches what it replaces — the Redis token row carried its own fresh
   * 10-minute TTL from the moment the callback wrote it, and the person still
   * has a project to choose.
   */
  attachPlatformToken(
    authState: AuthorizationState,
    platformAccessToken: string,
    platformRefreshToken?: string
  ): string {
    return sealAuthState(
      { ...authState, platformAccessToken, platformRefreshToken },
      authStateKey()
    );
  }

  /**
   * Create a new authorization state (step 1 of OAuth flow)
   * Returns a state ID and the PKCE code challenge for Insforge OAuth
   */
  async createAuthorizationState(params: {
    redirectUri: string;
    scope: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }): Promise<{ handle: string; sealedState: string; insforgeCodeChallenge: string }> {
    // Validate code_challenge_method early - only S256 is supported
    // Reject 'plain' and other methods to prevent downgrade attacks
    if (params.codeChallenge && params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
      throw new Error(`Unsupported code_challenge_method: ${params.codeChallengeMethod}. Only S256 is supported.`);
    }

    // Generate PKCE verifier for our request to Insforge
    const insforgeCodeVerifier = generateCodeVerifier();
    const insforgeCodeChallenge = generateCodeChallenge(insforgeCodeVerifier);

    // Normalize codeChallengeMethod to S256 if code challenge is provided
    const handle = newStateHandle();
    const authState: AuthorizationState = {
      ...params,
      handle,
      codeChallengeMethod: params.codeChallenge ? 'S256' : undefined,
      insforgeCodeVerifier,
      createdAt: Date.now(),
    };

    // The handle goes to the platform (32 chars, comfortably inside its
    // 255-character column); the sealed record goes in a cookie on our origin.
    return { handle, sealedState: sealAuthState(authState, authStateKey()), insforgeCodeChallenge };
  }

  /**
   * Get authorization state
   */
  async getAuthorizationState(sealed: string, expectedHandle: string): Promise<AuthorizationState | null> {
    // Null, not a throw, because every caller already treats "no such state" as
    // the ordinary case — a sign-in that took more than ten minutes. The reason
    // it failed is logged rather than returned: a caller that could distinguish
    // "expired" from "forged" would be an oracle for whoever is probing.
    try {
      const state = openAuthState<AuthorizationState>(sealed, authStateKey());
      // Required, not optional. An optional handle means a future caller can
      // drop the CSRF binding with no compile error — john-bot's note, and the
      // right fix is the signature rather than a comment asking nicely.
      if (state.handle !== expectedHandle) {
        // The cookie is real and ours, but it belongs to a different
        // authorization than the one the platform is calling back about. That
        // is the case the state parameter exists to catch.
        console.log('[OAuth] Authorization state handle does not match the state parameter');
        return null;
      }
      return state;
    } catch (error) {
      if (error instanceof InvalidAuthStateError) {
        console.log(`[OAuth] Authorization state rejected: ${error.message}`);
        return null;
      }
      throw error;
    }
  }

  /**
   * Create an authorization code after user approves and selects a project
   * Returns the code to be exchanged for a token
   */
  async createAuthorizationCode(
    stateId: string,
    handle: string,
    token: string,
    projectId: string
  ): Promise<string> {
    // Validate the state exists
    const authState = await this.getAuthorizationState(stateId, handle);
    if (!authState) {
      throw new Error('Invalid or expired authorization state');
    }

    // Validate token and get user info
    const user = await validateToken(token);

    // Still called for its refusal, not for its return value: this is where we
    // find out the signed-in user may actually reach the project they picked.
    // Everything it returns beyond the id is re-fetched per request through the
    // project-key cache, so none of it is sealed into the token — see
    // access-token.ts for why a caller-influenced field in there is a denial of
    // service against everyone who shares the project.
    const projectAccess = await getProjectAccess(token, projectId);

    const accessToken = issueAccessToken(
      {
        userId: user.id,
        platformAccessToken: token,
        projectId: projectAccess.projectId,
      },
      accessTokenKey()
    );

    // Ours, sealed here rather than at the token endpoint, so the code carries
    // two tokens of OURS instead of one of ours beside a raw platform
    // credential. The values it needs — user and project — are in scope at this
    // point and nowhere later, so building it anywhere else would mean
    // forwarding them for no reason.
    //
    // Undefined when the platform sent no refresh token: an older platform, or
    // a grant that does not issue one. That is a client without renewal, which
    // is exactly today's behaviour, rather than an error.
    const refreshToken = authState.platformRefreshToken
      ? issueRefreshToken(
          {
            userId: user.id,
            platformRefreshToken: authState.platformRefreshToken,
            projectId: projectAccess.projectId,
          },
          refreshTokenKey()
        )
      : undefined;

    // No binding row: the access token IS the record. See access-token.ts for
    // why the platform token goes in and the project API key deliberately does
    // not.

    // PKCE is REQUIRED for a sealed code, and this is the one place the
    // stateless rewrite genuinely tightens behaviour rather than preserving it.
    //
    // GETDEL made the stored code single-use: redeemed once, gone. A sealed
    // code cannot be single-use — there is nothing to delete — so it is
    // replayable for its lifetime. What makes that acceptable is PKCE: a
    // replayed code without the verifier is useless, and the verifier never
    // leaves the client. Without PKCE a replay is a full second session, so the
    // honest choice is to refuse rather than to issue a code we cannot protect.
    //
    // Nothing real is lost. The MCP spec requires PKCE of public clients, the
    // SDK always sends it, and our AS metadata already advertises S256 as the
    // only supported method — so this refuses a combination we never told
    // anyone we would accept.
    if (!authState.codeChallenge) {
      throw new Error(
        'PKCE is required: this server issues authorization codes that carry their own ' +
          'state, and the code_challenge is what stops a replayed code from being redeemed.'
      );
    }

    // The code IS the record. Five minutes, not the state's ten: RFC 6749
    // §4.1.2 wants a code short-lived, and a replayable one wants it more.
    const code = sealAuthState(
      {
        accessToken,
        refreshToken,
        redirectUri: authState.redirectUri,
        codeChallenge: authState.codeChallenge,
        codeChallengeMethod: authState.codeChallengeMethod,
      },
      authCodeKey(),
      Date.now(),
      AUTH_CODE_TTL
    );

    // Nothing to clean up: the state was never stored. It stops being accepted
    // when its own expiry passes.
    //
    // That does mean a sealed state is replayable inside its ten minutes, where
    // the deleted row was single-use. The bound on that is the platform: a
    // replay re-presents an authorization code the platform has already
    // consumed, and it refuses. So a replay reaches this method and then fails
    // at the exchange — it cannot mint a second session. Worth stating rather
    // than discovering, because "signed" and "single-use" are easy to conflate.
    return code;
  }

  /**
   * Exchange authorization code for token binding info
   * This is called by the MCP client after OAuth callback
   *
   * Uses atomic GETDEL to prevent authorization code replay attacks
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    // No GETDEL, because there is nothing stored. Replay is bounded by PKCE
    // (required at issue time) and by the five-minute expiry sealed inside.
    let payload: {
      accessToken: string;
      refreshToken?: string;
      redirectUri: string;
      codeChallenge?: string;
      codeChallengeMethod?: string;
    };
    try {
      payload = openAuthState(code, authCodeKey());
    } catch {
      throw new Error('Invalid or expired authorization code');
    }

    const { accessToken, refreshToken, redirectUri: storedRedirectUri, codeChallenge, codeChallengeMethod } = payload;

    // Validate redirect URI
    if (redirectUri !== storedRedirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // Unconditional now: a code without a challenge cannot be issued, so one
    // arriving without it is not ours to honour.
    if (!codeChallenge) {
      throw new Error('Authorization code is missing its code challenge');
    }
    {
      if (!codeVerifier) {
        throw new Error('Code verifier required');
      }

      // Explicitly validate code challenge method
      // Only S256 is secure; 'plain' is explicitly rejected per security best practices
      if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
        throw new Error(`Unsupported code_challenge_method: ${codeChallengeMethod}. Only S256 is supported.`);
      }

      // Always use S256 for verification (treat missing method as S256)
      const computedChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      if (computedChallenge !== codeChallenge) {
        throw new Error('Code verifier mismatch');
      }
    }

    return { accessToken, refreshToken };
  }
  /**
   * Everything a tool call needs, from the token alone plus one cached lookup.
   *
   * The token used to BE the Redis key; now it carries its own record. What it
   * deliberately does not carry is the project API key — that is fetched here,
   * from a 60-second cache, so the platform stays the authority on revocation.
   * See project-key-cache.ts for why that TTL is fixed rather than bounded by
   * the token's own expiry.
   */
  async resolveProjectFromToken(token: string): Promise<{
    apiKey: string;
    apiBaseUrl: string;
    projectId: string;
    projectName: string;
    userId: string;
    organizationId: string;
    oauthTokenHash: string;
  } | null> {
    const payload = readAccessToken(token, accessTokenKey());
    if (!payload) {
      // Not ours, tampered, or expired — all the same 401 to a caller, and
      // deliberately indistinguishable so nothing downstream can branch on it.
      return null;
    }

    const cache = getProjectKeyCache();
    let key = cache.get(payload.userId, payload.projectId);

    if (!key) {
      // Asked afresh, which is what makes a revoked grant stop working within
      // the cache TTL rather than at the end of the token's life.
      try {
        const access = await getProjectAccess(payload.platformAccessToken, payload.projectId);
        key = {
          apiKey: access.apiKey,
          accessHost: access.accessHost,
          projectName: access.projectName,
          organizationId: access.organizationId,
        };
        cache.set(payload.userId, payload.projectId, key);
      } catch (error) {
        // "REFUSED" AND "COULD NOT ASK" ARE DIFFERENT ANSWERS, and the first
        // version of this collapsed them into one.
        //
        // A 401 or 403 is the platform saying this user may no longer reach
        // this project: the credential is the problem, so the caller gets a
        // 401 and re-authorizes. Anything else — a 500, a timeout, DNS, a
        // rate limit — is us being unable to find out. Reporting that as
        // "your sign-in is no longer valid" is a lie the client acts on: it
        // throws away a perfectly good session and drags the user through a
        // browser login to fix a platform hiccup that would have cleared on
        // retry. The old binding held the key for 30 days, so a blip never
        // signed anyone out; making the lookup per-request is what introduced
        // this, and it needs the distinction the binding did not.
        //
        // Iris put the rule better than I did: 401 when the credential is the
        // problem, 5xx when we could not tell.
        if (isAuthorizationRefusal(error)) {
          console.log(
            `[OAuth] Project access refused for ${payload.userId}: ${
              error instanceof Error ? error.message : 'unknown'
            }`
          );
          return null;
        }

        console.error(
          `[OAuth] Could not reach the platform for ${payload.userId}; this is NOT a revocation:`,
          error
        );
        throw error;
      }
    }

    return {
      apiKey: key.apiKey,
      apiBaseUrl: key.accessHost,
      projectId: payload.projectId,
      projectName: key.projectName,
      userId: payload.userId,
      organizationId: key.organizationId,
      // A hash of the bearer, never the bearer itself — the analytics and
      // session fields want an opaque handle and nothing more.
      oauthTokenHash: hashToken(token),
    };
  }

  /**
   * Get all available projects for a user (for project selection UI)
   */
  async getAvailableProjects(token: string): Promise<Array<{
    organization: Organization;
    projects: Project[];
  }>> {
    return getAllUserProjects(token);
  }
}

// Singleton instance
let oauthManager: OAuthManager | null = null;

export function getOAuthManager(): OAuthManager {
  if (!oauthManager) {
    oauthManager = new OAuthManager();
  }
  return oauthManager;
}
