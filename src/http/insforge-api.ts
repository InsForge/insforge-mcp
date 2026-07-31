import fetch from 'node-fetch';

/**
 * Insforge Cloud Platform API Client
 * Used for OAuth token validation and project information retrieval
 */

// Default to production, can be overridden via environment variable
const INSFORGE_API_BASE = process.env.INSFORGE_API_BASE || 'https://api.insforge.dev';

/**
 * Organization from Insforge API
 */
export interface Organization {
  id: string;
  name: string;
  type: 'personal' | 'team' | 'company';
  created_at: string;
}

/**
 * Project from Insforge API
 */
export interface Project {
  id: string;
  organization_id: string;
  name: string;
  appkey: string;
  region: string;
  status: 'active' | 'paused' | 'deleted' | 'restoring';
  instance_type: string;
  created_at: string;
}

/**
 * Project with access information
 */
export interface ProjectAccess {
  projectId: string;
  projectName: string;
  organizationId: string;
  accessHost: string;
  apiKey: string;
  region: string;
  status: string;
}

/**
 * User profile from token validation
 */
export interface UserProfile {
  id: string;
  email: string;
  name?: string;
}

/**
 * Error from Insforge API
 */
export class InsforgeApiError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code?: string
  ) {
    super(message);
    this.name = 'InsforgeApiError';
  }
}

/**
 * How long we wait for the platform before calling it unreachable.
 *
 * Every call in this file had NO timeout, and that quietly made the 503 path
 * unreachable in the case it was written for. Measured against a socket that
 * accepts the connection and never answers — the shape an overloaded service
 * actually takes:
 *
 *   no timeout   still hanging at 30s   (undici's default headersTimeout is 300s)
 *
 * Cloudflare gives up at 100s and the MCP client long before that, so a stalled
 * platform produced a gateway timeout — never our "temporarily_unavailable"
 * with a Retry-After. The distinction between "refused" and "could not tell"
 * only exists if we find out promptly which one it is.
 *
 * So a failure has to be FAST as well as classified. 10s matches the one place
 * that already had a bound (the backend version check in the tool registrar) and
 * is comfortably inside every proxy in the chain. Note this is on the request
 * path for a cache miss, so it is also the worst case a user waits before being
 * told to retry.
 *
 * AbortSignal.timeout throws a TimeoutError, which is not an InsforgeApiError —
 * so isAuthorizationRefusal() reads it as "could not tell" and it becomes a 503.
 * That is the intended route, and it is why this needs no special-casing
 * downstream.
 */
const PLATFORM_TIMEOUT_MS = 10_000;

/**
 * The platform has TWO path families, and guessing costs you a 404.
 *
 * Measured against api.insforge.dev rather than inferred from the neighbours:
 *
 *   /auth/v1/profile         401   <- reachable      /api/auth/v1/profile      404
 *   /api/oauth/v1/revoke     401   <- reachable      /oauth/v1/revoke          404
 *
 * So user/org/project routes sit at the root and the OAuth routes sit under
 * `/api`. I got this wrong writing revokePlatformToken — it called
 * `/oauth/v1/revoke`, which 404s, so the revoke would have failed every single
 * time against the real platform while passing every local test.
 *
 * It passed because my stub matched `req.url.includes('/oauth/v1/revoke')`,
 * which is true of both paths. A stub that substring-matches cannot catch a
 * path error; the only thing that could was asking the real host. Hence this
 * constant, so the two families are named once instead of being retyped per
 * call site.
 */
const OAUTH_API_BASE = `${INSFORGE_API_BASE}/api/oauth/v1`;

/**
 * Every outbound call to the platform goes through this, so a new one cannot be
 * added without a bound. That is the actual defect being fixed: not a missing
 * timeout in one place, but six places each free to forget.
 */
function platformFetch(url: string, init: Parameters<typeof fetch>[1] = {}) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(PLATFORM_TIMEOUT_MS) });
}

/**
 * Validate OAuth token and get user profile
 */
export async function validateToken(token: string): Promise<UserProfile> {
  const response = await platformFetch(`${INSFORGE_API_BASE}/auth/v1/profile`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Token validation failed: ${errorText}`,
      response.status
    );
  }

  const data = await response.json() as { user: UserProfile };
  return data.user;
}

/**
 * Get all organizations for the authenticated user
 */
export async function getOrganizations(token: string): Promise<Organization[]> {
  const response = await platformFetch(`${INSFORGE_API_BASE}/organizations/v1`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Failed to get organizations: ${errorText}`,
      response.status
    );
  }

  const data = await response.json() as { organizations: Organization[] };
  return data.organizations;
}

/**
 * Get all projects for an organization
 */
export async function getProjects(token: string, organizationId: string): Promise<Project[]> {
  const response = await platformFetch(`${INSFORGE_API_BASE}/organizations/v1/${organizationId}/projects`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Failed to get projects: ${errorText}`,
      response.status
    );
  }

  const data = await response.json() as { projects: Project[] };
  return data.projects;
}

/**
 * Get project details
 */
export async function getProject(token: string, projectId: string): Promise<Project> {
  const response = await platformFetch(`${INSFORGE_API_BASE}/projects/v1/${projectId}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Failed to get project: ${errorText}`,
      response.status
    );
  }

  const data = await response.json() as { project: Project };
  return data.project;
}

/**
 * Get project access API key
 */
export async function getProjectApiKey(token: string, projectId: string): Promise<string> {
  const response = await platformFetch(`${INSFORGE_API_BASE}/projects/v1/${projectId}/access-api-key`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Failed to get project API key: ${errorText}`,
      response.status
    );
  }

  const data = await response.json() as { access_api_key: string };
  return data.access_api_key;
}

/**
 * Revoke a platform access token upstream (RFC 7009).
 *
 * This is what makes OUR /oauth/revoke mean something. With the token binding
 * gone, dropping our cached project key only forces one re-fetch — the sealed
 * bearer still carries a live platform token, so the very next request works
 * again and the credential stays usable for its full 24 hours. A revoke that
 * returns 200 and changes nothing is the worst kind of security control: the
 * person who called it believes the leak is closed.
 *
 * So revoke the thing that actually grants access. Iris confirmed the endpoint
 * is deployed and takes our client id with no client secret:
 *
 *   POST /oauth/v1/revoke  { token, token_type_hint, client_id }
 *   our client_id      -> 200 {"success":true}
 *   unknown client_id  -> 401 invalid_client
 *
 * Throws on any non-2xx, deliberately: the caller has to decide what a failed
 * revocation means, and it must not be reported to anyone as success.
 */
export async function revokePlatformToken(token: string, clientId: string): Promise<void> {
  const response = await platformFetch(`${OAUTH_API_BASE}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token,
      token_type_hint: 'access_token',
      client_id: clientId,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new InsforgeApiError(
      `Failed to revoke platform token: ${errorText}`,
      response.status
    );
  }
}

export interface PlatformTokens {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

/**
 * Exchange an authorization code for platform tokens.
 *
 * This lived in server.ts, doing its own bare `fetch`, and that placement was
 * the whole defect rather than an accident of style. When I wrapped the calls
 * in this file with a timeout I wrote "every outbound call to the platform goes
 * through this" — true of this file, false of the server, and this is the call
 * it missed. Iris found it by forcing the platform unroutable on a branch env:
 *
 *   platform reachable    callback -> 400 invalid_grant     (the platform's answer)
 *   platform unroutable   callback -> 500 "fetch failed"    no Retry-After
 *
 * `fetch failed` is Node's raw message rendered to whoever is looking, and this
 * is the ONE upstream call that renders in a human's browser mid-sign-in. So it
 * was both the least classified and the most visible.
 *
 * Moving it here rather than adding a timeout where it stood: a call that lives
 * beside its siblings inherits their bound automatically, and the next person
 * adding a platform call finds them all in one file. The fix for "six places
 * free to forget" cannot itself be a seventh place to remember.
 *
 * Throws InsforgeApiError for a platform response we could not read, and
 * returns the parsed body otherwise — INCLUDING an OAuth error body, because
 * `invalid_grant` is the platform answering, not a failure to reach it. The
 * caller needs those two apart.
 */
export async function exchangePlatformCode(params: {
  code: string;
  redirectUri: string;
  clientId: string;
  clientSecret: string;
  codeVerifier: string;
}): Promise<PlatformTokens> {
  const response = await platformFetch(`${OAUTH_API_BASE}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      client_id: params.clientId,
      client_secret: params.clientSecret,
      code_verifier: params.codeVerifier,
    }),
  });

  try {
    return (await response.json()) as PlatformTokens;
  } catch {
    // A response we cannot parse is not the platform declining — it is the
    // platform, or something between us and it, not answering properly.
    throw new InsforgeApiError(
      `Token exchange returned an unreadable response (HTTP ${response.status})`,
      response.status
    );
  }
}

/**
 * Build the access host URL for a project
 * Format: https://{appkey}.{region}.insforge.app
 */
export function buildAccessHost(project: Project): string {
  // Check if project has a customized domain
  if ((project as any).customized_domain) {
    return `https://${(project as any).customized_domain}`;
  }

  // Standard format: https://{appkey}.{region}.insforge.app
  return `https://${project.appkey}.${project.region}.insforge.app`;
}

/**
 * Get complete project access information
 * This is the main function used to resolve project info from OAuth token + project selection
 */
export async function getProjectAccess(
  token: string,
  projectId: string
): Promise<ProjectAccess> {
  // Get project details and API key in parallel
  const [project, apiKey] = await Promise.all([
    getProject(token, projectId),
    getProjectApiKey(token, projectId),
  ]);

  return {
    projectId: project.id,
    projectName: project.name,
    organizationId: project.organization_id,
    accessHost: buildAccessHost(project),
    apiKey,
    region: project.region,
    status: project.status,
  };
}

/**
 * Get all projects across all organizations (for project selection UI)
 */
export async function getAllUserProjects(token: string): Promise<Array<{
  organization: Organization;
  projects: Project[];
}>> {
  const organizations = await getOrganizations(token);

  const results = await Promise.all(
    organizations.map(async (org) => {
      const projects = await getProjects(token, org.id);
      return {
        organization: org,
        projects: projects.filter(p => p.status === 'active'), // Only active projects
      };
    })
  );

  return results.filter(r => r.projects.length > 0); // Only orgs with active projects
}
