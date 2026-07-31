/**
 * The project API key, fetched per request and cached briefly.
 *
 * It used to live in the token binding, written once at sign-in and reused for
 * thirty days. That is what made the binding necessary, and it had two
 * consequences nobody chose: a rotated project key kept working until the
 * binding expired, and the MCP could not survive a restart.
 *
 * So fetch it instead. The cost is a platform round-trip, and Iris measured the
 * floor: ~60ms of platform server time, location-independent, on a route that
 * does nothing. On tools that otherwise take 20ms that is the dominant cost —
 * which is why this cache is part of the change rather than an optimisation.
 *
 * THE TTL IS FIXED AND SHORT, AND THAT IS THE WHOLE DESIGN. With the binding
 * gone there is no row to delete, so revocation belongs to the platform:
 * `validateAccessToken` checks `revoked` on every call. Caching bounded by the
 * token's own `exp` — which is what I first specced — would have made the
 * platform's revoke endpoint a no-op from our side for the life of the token.
 * Sixty seconds is the bound on how stale a revocation can be, and it is the
 * number that keeps "revoke" meaning something.
 */

export const PROJECT_KEY_TTL_MS = 60 * 1000;

export interface ProjectKey {
  apiKey: string;
  accessHost: string;
  projectName: string;
  organizationId: string;
}

interface Entry {
  value: ProjectKey;
  expiresAt: number;
}

/**
 * Keyed by user AND project.
 *
 * Not by project alone: two users can both reach one project with different
 * grants, and a cache keyed on the project would serve one user's key to the
 * other. That is the shape of a cross-tenant bug, so the key is the pair.
 */
function cacheKey(userId: string, projectId: string): string {
  return `${userId} ${projectId}`;
}

export class ProjectKeyCache {
  private entries = new Map<string, Entry>();

  /**
   * The cached key, or undefined. Expiry is checked on read rather than swept:
   * an entry nobody asks for again costs one Map slot for 60 seconds, and a
   * sweeper for that would be more machinery than the thing it manages.
   */
  get(userId: string, projectId: string, now: number = Date.now()): ProjectKey | undefined {
    const key = cacheKey(userId, projectId);
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (now >= entry.expiresAt) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(userId: string, projectId: string, value: ProjectKey, now: number = Date.now()): void {
    this.entries.set(cacheKey(userId, projectId), { value, expiresAt: now + PROJECT_KEY_TTL_MS });
  }

  /**
   * Drop everything for one user.
   *
   * The one case where a stale entry is actively wrong rather than merely old:
   * a sign-out. Cheap, and it means a revoked session cannot keep using a key
   * we already handed ourselves.
   */
  forgetUser(userId: string): void {
    const prefix = `${userId} `;
    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix)) this.entries.delete(key);
    }
  }

  /** For /health, so the cache is observable rather than a black box. */
  size(): number {
    return this.entries.size;
  }
}

let cache: ProjectKeyCache | null = null;

export function getProjectKeyCache(): ProjectKeyCache {
  if (!cache) cache = new ProjectKeyCache();
  return cache;
}
