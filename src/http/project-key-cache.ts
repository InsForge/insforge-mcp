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

/**
 * How often the write path is allowed to scan for expired entries.
 *
 * The first version checked expiry on read only, and its comment claimed an
 * unread entry "costs one Map slot for 60 seconds". Quinn measured it: it costs
 * one Map slot FOREVER.
 *
 *   10,000 entries written, one more an hour later, nothing re-read -> 10,001
 *
 * Every one of those slots holds a project API key, in memory, long past the
 * TTL that exists to bound exactly that — for the life of the container and
 * across every user who ever signed in. `forgetUser` only fires on sign-out,
 * which is the case that already ends well.
 *
 * So eviction moves to the write path. Rate-limited rather than run on every
 * `set`, because the scan is O(n) and the write path is per-request: at one
 * scan per second the cost is bounded whatever the request rate, and an expired
 * entry outlives its expiry by at most a second.
 *
 * Deliberately NOT a timer. A background sweeper for a 60-second cache is more
 * machinery than the thing it manages, and it would keep a container awake to
 * tidy a Map. The honest residual: if writes stop entirely, the last window's
 * entries stay until the next write — bounded by one TTL window rather than
 * unbounded, which was the defect.
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
 * other. That is the shape of a cross-tenant bug, so the key is the pair.
 *
 * THE NESTING IS THE FIX, and it replaces a `${userId} ${projectId}` join that
 * Quinn broke in two lines:
 *
 *   set('a',   'b c', FIRST)      both produce the key "a b c"
 *   set('a b', 'c',   SECOND)
 *   get('a',   'b c')  ->  SECOND — one entry, another user's key
 *
 * Not reachable today: both values are platform UUIDs. But `project_id` is
 * about to become a tool argument, and then a caller who can put a space in it
 * is aiming at a chosen cache slot. The paragraph above says the pair IS the
 * key precisely to prevent cross-tenant serving, so an encoding under which two
 * pairs collide contradicts the thing it was written for.
 *
 * A delimiter would close this instance. Nesting closes the CLASS: two maps
 * cannot collide whatever the strings contain, there is no separator for a
 * caller to smuggle, and nobody has to keep obeying a rule about which
 * character is reserved. It also makes forgetUser a single delete instead of a
 * prefix scan over every entry — and that prefix scan was the same
 * joined-string assumption, one method further down.
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
   * Drop everything for one user.
   *
   * The one case where a stale entry is actively wrong rather than merely old:
   * a sign-out. Now a single delete rather than a scan over every entry in the
   * cache, because the user is a level of the structure rather than a prefix of
   * a string.
   */
  forgetUser(userId: string): void {
    this.byUser.delete(userId);
  }

  /** For /health, so the cache is observable rather than a black box. */
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
