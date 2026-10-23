/**
 * The project API key, fetched per request and cached briefly.
 *
 * Not stored for the life of a sign-in: a key frozen that long keeps working
 * after rotation. The platform round-trip costs ~60ms, which dominates tools
 * that otherwise take 20ms, so the cache is part of the design rather than an
 * optimisation.
 *
 * THE TTL IS FIXED AND SHORT, AND THAT IS THE WHOLE DESIGN. A cache hit is
 * served without asking the platform. A miss has resolveProjectFromToken call
 * getProjectAccess with the platform access token, and the platform enforces
 * its own revocation on that call (a 401/403 refusal becomes a 401 to the
 * client). Caching bounded by the token's own `exp` would make the platform's
 * revoke a no-op from our side for the life of the token. Sixty seconds is the
 * bound on how stale a revocation can be: a revoked grant keeps working for at
 * most one TTL after its last cache miss.
 */

export const PROJECT_KEY_TTL_MS = 60 * 1000;

/**
 * How often the write path is allowed to scan for expired entries.
 *
 * Expiry checked on read alone leaves every never-re-read entry, each holding
 * a project API key, in the Map for the life of the container. So eviction
 * runs on the write path, rate-limited because the scan is O(n) and the write
 * path is per-request: at most one full scan per second, whatever the request
 * rate.
 *
 * Deliberately NOT a timer: a background sweeper would keep a container awake
 * to tidy a 60-second Map. The cost is that how long an expired entry lingers
 * is bounded by write cadence, not by time. It is dropped by the first `set`
 * that lands at least a second after the previous scan: within a second of
 * expiry under steady traffic, after however long the gap is when writes are
 * sparse, and not at all if writes stop, unless that same key is read (which
 * deletes it) or its user signs out (forgetUser).
 */
const EVICTION_SCAN_INTERVAL_MS = 1000;

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
 * Keyed by user AND project, as a map of maps rather than a joined string.
 *
 * Not by project alone: two users can both reach one project with different
 * grants, and a cache keyed on the project would serve one user's key to the
 * other. Not a `${userId} ${projectId}` join either: ('a', 'b c') and
 * ('a b', 'c') produce the same key, so a caller who can put a separator in
 * either value is aiming at a chosen cache slot. Nesting closes the class: two
 * maps cannot collide whatever the strings contain, and forgetUser is a single
 * delete.
 */
export class ProjectKeyCache {
  private byUser = new Map<string, Map<string, Entry>>();
  private lastScanAt = 0;

  /**
   * The cached key, or undefined. Expiry is still checked here: a read must
   * never serve a stale key, whether or not a write has swept it yet.
   */
  get(userId: string, projectId: string, now: number = Date.now()): ProjectKey | undefined {
    const forUser = this.byUser.get(userId);
    if (!forUser) return undefined;

    const entry = forUser.get(projectId);
    if (!entry) return undefined;

    if (now >= entry.expiresAt) {
      forUser.delete(projectId);
      if (forUser.size === 0) this.byUser.delete(userId);
      return undefined;
    }
    return entry.value;
  }

  set(userId: string, projectId: string, value: ProjectKey, now: number = Date.now()): void {
    let forUser = this.byUser.get(userId);
    if (!forUser) {
      forUser = new Map();
      this.byUser.set(userId, forUser);
    }
    forUser.set(projectId, { value, expiresAt: now + PROJECT_KEY_TTL_MS });

    this.evictExpired(now);
  }

  /**
   * Drop everything for one user: the one case where a stale entry is actively
   * wrong rather than merely old, a sign-out.
   */
  forgetUser(userId: string): void {
    this.byUser.delete(userId);
  }

  /** Total number of cached entries across all users. */
  size(): number {
    let total = 0;
    for (const forUser of this.byUser.values()) total += forUser.size;
    return total;
  }

  /**
   * Drop everything expired. Rate-limited — see EVICTION_SCAN_INTERVAL_MS for
   * why this runs on the write path at most once a second rather than on every
   * write or on a timer.
   */
  private evictExpired(now: number): void {
    if (now - this.lastScanAt < EVICTION_SCAN_INTERVAL_MS) return;
    this.lastScanAt = now;

    for (const [userId, forUser] of this.byUser) {
      for (const [projectId, entry] of forUser) {
        if (now >= entry.expiresAt) forUser.delete(projectId);
      }
      if (forUser.size === 0) this.byUser.delete(userId);
    }
  }
}

let cache: ProjectKeyCache | null = null;

export function getProjectKeyCache(): ProjectKeyCache {
  if (!cache) cache = new ProjectKeyCache();
  return cache;
}
