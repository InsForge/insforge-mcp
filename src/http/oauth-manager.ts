import { createHash, randomBytes } from 'crypto';
import { getRedisClient } from './redis.js';
import { sealAuthState, openAuthState, InvalidAuthStateError } from './auth-state.js';
import { newStateHandle } from './auth-state-cookie.js';
import { authStateKey } from './config.js';
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
 * OAuth authorization state stored in Redis
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

  createdAt: number;
}

/**
 * Token binding stored in Redis
 * Links an OAuth token to a specific project
 */
interface TokenBinding {
  tokenHash: string;
  userId: string;
  userEmail: string;
  projectId: string;
  projectName: string;
  organizationId: string;
  accessHost: string;
  apiKey: string;
  createdAt: number;
  lastUsedAt: number;
}

// Redis key prefixes
const TOKEN_BINDING_PREFIX = 'mcp:auth:binding:';
const AUTH_CODE_PREFIX = 'mcp:auth:code:';

// TTLs
const AUTH_CODE_TTL = 5 * 60; // 5 minutes
const TOKEN_BINDING_TTL = 30 * 24 * 60 * 60; // 30 days

/**
 * Generate a hash of the token for storage
 */
function hashToken(token: string): string {
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
  attachPlatformToken(authState: AuthorizationState, platformAccessToken: string): string {
    return sealAuthState({ ...authState, platformAccessToken }, authStateKey());
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
    const redis = getRedisClient();

    // Validate the state exists
    const authState = await this.getAuthorizationState(stateId, handle);
    if (!authState) {
      throw new Error('Invalid or expired authorization state');
    }

    // Validate token and get user info
    const user = await validateToken(token);

    // Get project access info
    const projectAccess = await getProjectAccess(token, projectId);

    // Create token binding
    const tokenHash = hashToken(token);
    const binding: TokenBinding = {
      tokenHash,
      userId: user.id,
      userEmail: user.email,
      projectId: projectAccess.projectId,
      projectName: projectAccess.projectName,
      organizationId: projectAccess.organizationId,
      accessHost: projectAccess.accessHost,
      apiKey: projectAccess.apiKey,
      createdAt: Date.now(),
      lastUsedAt: Date.now(),
    };

    // Store the binding
    await redis.setex(
      TOKEN_BINDING_PREFIX + tokenHash,
      TOKEN_BINDING_TTL,
      JSON.stringify(binding)
    );

    // Create authorization code that references the token hash
    const code = generateCode();
    await redis.setex(
      AUTH_CODE_PREFIX + code,
      AUTH_CODE_TTL,
      JSON.stringify({
        tokenHash,
        stateId,
        redirectUri: authState.redirectUri,
        codeChallenge: authState.codeChallenge,
        codeChallengeMethod: authState.codeChallengeMethod,
      })
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
  ): Promise<{ tokenHash: string }> {
    const redis = getRedisClient();

    // Atomically get and delete the code to prevent replay attacks
    // GETDEL returns the value and deletes the key in one operation
    const codeData = await redis.getdel(AUTH_CODE_PREFIX + code);

    if (!codeData) {
      throw new Error('Invalid or expired authorization code');
    }

    const { tokenHash, redirectUri: storedRedirectUri, codeChallenge, codeChallengeMethod } =
      JSON.parse(codeData);

    // Validate redirect URI
    if (redirectUri !== storedRedirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // Validate PKCE if code challenge was provided during authorization
    if (codeChallenge) {
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

    return { tokenHash };
  }

  /**
   * Get token binding by token hash
   */
  async getTokenBinding(tokenHash: string): Promise<TokenBinding | null> {
    const redis = getRedisClient();
    const data = await redis.get(TOKEN_BINDING_PREFIX + tokenHash);

    if (!data) {
      return null;
    }

    return JSON.parse(data) as TokenBinding;
  }

  /**
   * Get token binding by raw token
   */
  async getBindingByToken(token: string): Promise<TokenBinding | null> {
    const tokenHash = hashToken(token);
    return this.getTokenBinding(tokenHash);
  }

  /**
   * Update last used time for a token binding
   */
  async touchBinding(tokenHash: string): Promise<void> {
    const redis = getRedisClient();
    const binding = await this.getTokenBinding(tokenHash);

    if (binding) {
      binding.lastUsedAt = Date.now();
      await redis.setex(
        TOKEN_BINDING_PREFIX + tokenHash,
        TOKEN_BINDING_TTL,
        JSON.stringify(binding)
      );
    }
  }

  /**
   * Revoke a token binding
   */
  async revokeBinding(tokenHash: string): Promise<void> {
    const redis = getRedisClient();
    await redis.del(TOKEN_BINDING_PREFIX + tokenHash);
  }

  /**
   * Resolve project info from OAuth token or tokenHash
   * This is the main entry point used by the MCP server
   *
   * The token parameter can be either:
   * 1. A tokenHash (returned by /oauth/token endpoint) - used by MCP clients after OAuth
   * 2. A raw Insforge OAuth token - used for direct API access
   *
   * Flow:
   * 1. Try to find binding using token directly as tokenHash
   * 2. If not found, try hashing the token and look up again
   * 3. If still not found, return null (client needs to go through OAuth flow)
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
    // First, try using the token directly as a tokenHash
    // This handles the case where MCP clients send the tokenHash from /oauth/token
    let binding = await this.getTokenBinding(token);
    let actualTokenHash = token;

    if (!binding) {
      // Try hashing the token (in case it's a raw Insforge token)
      actualTokenHash = hashToken(token);
      binding = await this.getTokenBinding(actualTokenHash);
    }

    if (!binding) {
      // No binding found - client needs to complete OAuth flow
      return null;
    }

    // Update last used time
    await this.touchBinding(actualTokenHash);

    return {
      apiKey: binding.apiKey,
      apiBaseUrl: binding.accessHost,
      projectId: binding.projectId,
      projectName: binding.projectName,
      userId: binding.userId,
      organizationId: binding.organizationId,
      oauthTokenHash: actualTokenHash,
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

  /**
   * Bind a token to a project directly (skip OAuth code flow)
   * Used when user selects a project via API
   */
  async bindTokenToProject(token: string, projectId: string): Promise<TokenBinding> {
    const redis = getRedisClient();

    // Validate token and get user info
    const user = await validateToken(token);

    // Get project access info
    const projectAccess = await getProjectAccess(token, projectId);

    // Create token binding
    const tokenHash = hashToken(token);
    const binding: TokenBinding = {
      tokenHash,
      userId: user.id,
      userEmail: user.email,
      projectId: projectAccess.projectId,
      projectName: projectAccess.projectName,
      organizationId: projectAccess.organizationId,
      accessHost: projectAccess.accessHost,
      apiKey: projectAccess.apiKey,
      createdAt: Date.now(),
      lastUsedAt: Date.now(),
    };

    // Store the binding
    await redis.setex(
      TOKEN_BINDING_PREFIX + tokenHash,
      TOKEN_BINDING_TTL,
      JSON.stringify(binding)
    );

    console.log(`[OAuthManager] Token bound to project: ${projectAccess.projectName}`);
    return binding;
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
