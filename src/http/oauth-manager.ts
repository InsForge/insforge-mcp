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
  type Organization,
  type Project,
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

  // Original MCP client request. clientId is deliberately NOT here: nothing
  // reads it after authorize, and at up to 4096 characters it pushes the sealed
  // envelope past the 4096-byte cookie bound.
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;  // From MCP client (if using PKCE)
  codeChallengeMethod?: string;

  // Our PKCE verifier for calling Insforge OAuth
  insforgeCodeVerifier: string;

  /**
   * The platform access token, present only AFTER the callback has exchanged
   * the code for it. Safe here only because this envelope is encrypted, not
   * signed: a bearer token in a readable blob would be a bearer token in a URL.
   */
  platformAccessToken?: string;

  /**
   * The platform REFRESH token, from the same exchange. Safe here for the same
   * reason as its neighbour, and it needs that reason more: it outlives the
   * access token by thirty days to one hour.
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
 * OAuthManager handles the OAuth authorization flow and token-to-project binding
 */
export class OAuthManager {
  /**
   * Re-seal an existing state with the platform token attached.
   *
   * Returns a NEW sealed value: the sealed value IS the record, so adding a
   * field necessarily produces a different string. The expiry restarts here;
   * the person still has a project to choose.
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

    const insforgeCodeVerifier = generateCodeVerifier();
    const insforgeCodeChallenge = generateCodeChallenge(insforgeCodeVerifier);

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
      // expectedHandle is required, not optional: an optional one would let a
      // caller drop the CSRF binding with no compile error.
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
    const authState = await this.getAuthorizationState(stateId, handle);
    if (!authState) {
      throw new Error('Invalid or expired authorization state');
    }

    const user = await validateToken(token);

    // Called for its refusal: this is where we learn the signed-in user may
    // reach the project they picked. Nothing beyond the id is sealed into the
    // token — see access-token.ts for why a caller-influenced field there is a
    // denial of service against everyone who shares the project.
    const projectAccess = await getProjectAccess(token, projectId);

    const accessToken = issueAccessToken(
      {
        userId: user.id,
        platformAccessToken: token,
        projectId: projectAccess.projectId,
      },
      accessTokenKey()
    );

    // Sealed here rather than at the token endpoint, so the code carries two
    // tokens of OURS instead of one of ours beside a raw platform credential.
    // Undefined when the platform sent no refresh token (an older platform, or
    // a grant that issues none): a client without renewal, not an error.
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

    // PKCE is REQUIRED for a sealed code. A sealed code cannot be single-use —
    // there is nothing to delete — so it is replayable for its lifetime, and
    // PKCE is what makes that acceptable: a replayed code without the verifier
    // is useless. Without PKCE a replay is a full second session, so refuse
    // rather than issue a code we cannot protect.
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

    // The state was never stored, so it stays acceptable until its own expiry:
    // a sealed state is replayable inside its ten minutes. Which hop that
    // reaches depends on what is replayed. The callback re-presents the
    // platform's authorization code, which the platform has already consumed,
    // so that replay fails there. This step runs on the platform access token
    // the callback sealed into the state, which the platform still honours, so
    // a replayed project selection mints a second code. What bounds that: the
    // replayer must hold the sealed cookie, server.ts clears it when the flow
    // completes, and the second code is redeemable only with the verifier of
    // the client that started the flow.
    return code;
  }

  /**
   * Exchange an authorization code for the tokens sealed inside it.
   * Called by the MCP client after the OAuth callback.
   *
   * Nothing is stored, so there is no single-use delete: replay is bounded by
   * PKCE (required at issue time) and by the five-minute expiry sealed inside.
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
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

    if (redirectUri !== storedRedirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // A code without a challenge cannot be issued, so one arriving without it
    // is not ours to honour.
    if (!codeChallenge) {
      throw new Error('Authorization code is missing its code challenge');
    }
    if (!codeVerifier) {
      throw new Error('Code verifier required');
    }

    // Only S256; 'plain' is rejected.
    if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
      throw new Error(`Unsupported code_challenge_method: ${codeChallengeMethod}. Only S256 is supported.`);
    }

    // A missing method is treated as S256.
    const computedChallenge = createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    if (computedChallenge !== codeChallenge) {
      throw new Error('Code verifier mismatch');
    }

    return { accessToken, refreshToken };
  }

  /**
   * Everything a tool call needs, from the token alone plus one cached lookup.
   *
   * The token deliberately does not carry the project API key — that is fetched
   * here, from a 60-second cache, so the platform stays the authority on
   * revocation. See project-key-cache.ts for why that TTL is fixed rather than
   * bounded by the token's own expiry.
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
        // "Refused" and "could not ask" are different answers. A 401 or 403 is
        // the platform saying this user may no longer reach this project: the
        // caller gets a 401 and re-authorizes. Anything else — a 500, a timeout,
        // DNS, a rate limit — is us being unable to find out, and reporting it
        // as "your sign-in is no longer valid" makes the client throw away a
        // good session over a blip that would have cleared on retry.
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
