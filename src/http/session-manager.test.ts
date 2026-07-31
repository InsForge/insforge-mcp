import { describe, it, expect, vi } from 'vitest';
import {
  SessionManager,
  selectOrphanedSessions,
  routeForSessionRequest,
  SESSION_TTL_MS,
  monotonicNow,
} from './session-manager.js';

/**
 * No Redis mock at the top of this file any more, and its absence is the point.
 * Every test below used to begin by deciding what Redis would say; the ones
 * about Redis losing, wiping or garbling its records are gone with the store
 * that could do those things.
 *
 * What replaces them is the same set of questions asked of the one clock that
 * is left, plus the routing contract a client depends on to recover.
 */

/** A session whose last traffic is old enough to be collectable. */
const STALE = -(SESSION_TTL_MS + 1000);
/** A session that served traffic a minute ago. */
const FRESH = -60_000;

/** Stand-in for a session entry; only close() is exercised by the sweep. */
function fakeRuntime(transportType: 'streamable' | 'sse' = 'streamable', ageOffsetMs = STALE) {
  return {
    server: { close: vi.fn().mockResolvedValue(undefined) },
    transport: { close: vi.fn().mockResolvedValue(undefined) },
    transportType,
    data: {
      apiKey: 'ik_x',
      apiBaseUrl: 'https://p.insforge.app',
      projectId: 'proj_1',
      projectName: 'demo',
      userId: 'user_1',
      organizationId: 'org_1',
      oauthTokenHash: 'hash',
      createdAt: 0,
      lastAccessedAt: 0,
    },
    lastSeenAt: monotonicNow() + ageOffsetMs,
    openStreams: 0,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function seed(
  manager: any,
  ids: string[],
  transportType: 'streamable' | 'sse' = 'streamable',
  ageOffsetMs = STALE
) {
  const runtimes = new Map<string, ReturnType<typeof fakeRuntime>>();
  for (const id of ids) {
    const rt = fakeRuntime(transportType, ageOffsetMs);
    runtimes.set(id, rt);
    manager.runtimeSessions.set(id, rt);
  }
  return runtimes;
}

describe('routeForSessionRequest', () => {
  /**
   * The branch order of POST /mcp. Pinned here because the two failure
   * outcomes look interchangeable and are not: 404 is what makes a client
   * start a new session, 400 tells it the request was malformed.
   */

  it('sends an unknown session id to 404, not 400', () => {
    // The whole restart story. A client holding a session id from before a
    // restart must be told to initialize again, and 404 is the only status the
    // protocol assigns that meaning.
    expect(routeForSessionRequest({ hasRuntime: false, sessionId: 'gone', isInitialize: false }))
      .toBe('not-found');
  });

  it('lets an initialize through even when it carries a stale session id', () => {
    // The case that decides the branch ORDER, and the one that would break
    // silently if someone reordered them: a reconnecting client sends exactly
    // this. Routing it to 404 would answer "not found" to the very request
    // that repairs the situation, and the client would loop.
    expect(routeForSessionRequest({ hasRuntime: false, sessionId: 'stale', isInitialize: true }))
      .toBe('create');
  });

  it('uses the session we already hold', () => {
    expect(routeForSessionRequest({ hasRuntime: true, sessionId: 'live', isInitialize: false }))
      .toBe('use-existing');
  });

  it('prefers the held session even for an initialize', () => {
    expect(routeForSessionRequest({ hasRuntime: true, sessionId: 'live', isInitialize: true }))
      .toBe('use-existing');
  });

  it('creates on an initialize with no session id', () => {
    expect(routeForSessionRequest({ hasRuntime: false, isInitialize: true })).toBe('create');
  });

  it('keeps 400 for a request with no session id and no initialize', () => {
    // Genuinely malformed: nothing to recover, so this must NOT become a 404.
    // A 404 here would tell a client to re-initialize a session it never had.
    expect(routeForSessionRequest({ hasRuntime: false, isInitialize: false })).toBe('no-session');
    expect(routeForSessionRequest({ hasRuntime: false, sessionId: '', isInitialize: false }))
      .toBe('no-session');
  });
});

describe('selectOrphanedSessions', () => {
  const now = 1_800_000_000_000;

  it('collects a session nobody has touched for the TTL', () => {
    const s = [{ sessionId: 'abandoned', lastSeenAt: now - SESSION_TTL_MS - 1, openStreams: 0 }];
    expect(selectOrphanedSessions(s, now)).toEqual(['abandoned']);
  });

  it('leaves a session that served traffic recently', () => {
    const s = [{ sessionId: 'busy', lastSeenAt: now - 60_000, openStreams: 0 }];
    expect(selectOrphanedSessions(s, now)).toEqual([]);
  });

  it('separates the active from the abandoned in one pass', () => {
    const mixed = [
      { sessionId: 'active', lastSeenAt: now - 60_000, openStreams: 0 },
      { sessionId: 'abandoned', lastSeenAt: now - SESSION_TTL_MS - 1, openStreams: 0 },
    ];
    expect(selectOrphanedSessions(mixed, now)).toEqual(['abandoned']);
  });

  it('holds a session with an open stream, however old its clock is', () => {
    // NOT redundant with the age gate, and the reason this survived the Redis
    // deletion: a client holding GET /mcp open sends no requests, so nothing
    // stamps lastSeenAt while it is plainly still connected.
    const streaming = [
      { sessionId: 'listening', lastSeenAt: now - SESSION_TTL_MS * 10, openStreams: 1 },
    ];
    expect(selectOrphanedSessions(streaming, now)).toEqual([]);
  });

  it('reaps once the last stream has closed', () => {
    const closed = [
      { sessionId: 'was-listening', lastSeenAt: now - SESSION_TTL_MS - 1, openStreams: 0 },
    ];
    expect(selectOrphanedSessions(closed, now)).toEqual(['was-listening']);
  });

  it('reaps a session exactly at the TTL boundary', () => {
    const boundary = [{ sessionId: 'edge', lastSeenAt: now - SESSION_TTL_MS, openStreams: 0 }];
    expect(selectOrphanedSessions(boundary, now)).toEqual(['edge']);
  });
});

describe('SessionManager.sweepOrphanedSessions', () => {
  it('is a no-op with nothing in memory', async () => {
    const manager = new SessionManager();
    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
  });

  it('closes and drops only the idle sessions', async () => {
    const manager = new SessionManager();
    const runtimes = seed(manager, ['expired'], 'streamable', STALE);
    seed(manager, ['live'], 'streamable', FRESH);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(1);
    expect(manager.getActiveSessionIds()).toEqual(['live']);
    expect(runtimes.get('expired')!.server.close).toHaveBeenCalled();
    expect(runtimes.get('expired')!.transport.close).toHaveBeenCalled();
  });

  it('never reaps an SSE session, however idle it looks', async () => {
    // SSE cleans up on res 'close', and nothing on its message path stamps a
    // session, so an SSE session reads as idle from creation while the
    // connection is open and keepalive-warm. Sweeping it would drop a live
    // client. This asymmetry survives the Redis removal unchanged.
    const manager = new SessionManager();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sse = seed(manager as any, ['sse-live'], 'sse');

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toContain('sse-live');
    expect(sse.get('sse-live')!.transport.close).not.toHaveBeenCalled();
  });

  it('reaps an idle streamable session while leaving an SSE one alone', async () => {
    const manager = new SessionManager();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const streamable = seed(manager as any, ['http-dead'], 'streamable');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sse = seed(manager as any, ['sse-live'], 'sse');

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(1);
    expect(manager.getActiveSessionIds()).toEqual(['sse-live']);
    expect(streamable.get('http-dead')!.transport.close).toHaveBeenCalled();
    expect(sse.get('sse-live')!.transport.close).not.toHaveBeenCalled();
  });

  it('reclaims an accumulation of orphans in one pass', async () => {
    // The production shape: many sessions, few of them active. This is now the
    // ONLY thing that bounds memory — roughly 252 kB per session against a
    // ~493 MB heap limit, so a sweep that stopped working is a crash in hours.
    const manager = new SessionManager();
    seed(manager, Array.from({ length: 45 }, (_, i) => `dead${i}`), 'streamable', STALE);
    seed(manager, Array.from({ length: 5 }, (_, i) => `live${i}`), 'streamable', FRESH);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(45);
    expect(manager.getActiveSessionIds()).toHaveLength(5);
  });

  it('never reaps a streamable session while its stream is open', async () => {
    // Quinn's case: the client holds GET /mcp open and sends no POSTs, so
    // lastSeenAt is frozen at the moment the stream opened.
    const manager = new SessionManager();
    const runtimes = seed(manager, ['listening'], 'streamable', STALE);
    manager.openStream('listening');

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toEqual(['listening']);
    expect(runtimes.get('listening')!.transport.close).not.toHaveBeenCalled();
  });

  it('collects the session once the stream closes and it goes idle', async () => {
    const manager = new SessionManager();
    seed(manager, ['listening'], 'streamable', STALE);
    manager.openStream('listening');
    manager.closeStream('listening');
    // closeStream restarts the idle clock, so it is not immediately collectable.
    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (manager as any).runtimeSessions.get('listening').lastSeenAt = monotonicNow() + STALE;
    await expect(manager.sweepOrphanedSessions()).resolves.toBe(1);
    expect(manager.getActiveSessionIds()).toEqual([]);
  });

  it('counts overlapping streams so a reconnect cannot unprotect the session', async () => {
    // A client may open its replacement stream before the old response has
    // finished closing. A boolean flag cleared by the departing one would drop
    // the guard while a live stream is still attached.
    const manager = new SessionManager();
    seed(manager, ['reconnecting'], 'streamable', STALE);
    manager.openStream('reconnecting');
    manager.openStream('reconnecting');
    manager.closeStream('reconnecting');
    expect(manager.getOpenStreamCount('reconnecting')).toBe(1);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
  });

  it('ignores a stream close for a session that is already gone', async () => {
    const manager = new SessionManager();
    expect(() => manager.closeStream('never-existed')).not.toThrow();
    expect(manager.getOpenStreamCount('never-existed')).toBe(0);
  });

  it('a touch inside the sweep window saves the session', async () => {
    // The re-check before closing. The sweep awaits deleteSession for each id,
    // so a request can land between the snapshot and this session's turn.
    const manager = new SessionManager();
    seed(manager, ['revived'], 'streamable', STALE);

    manager.touchSession('revived');

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toEqual(['revived']);
  });

  it('drops a session whose close throws, rather than holding it forever', async () => {
    // The sweep only reaps what it can close, so an entry left behind by a
    // failed close would never be collected again — a permanent leak of the
    // one resource nothing else bounds.
    const manager = new SessionManager();
    const runtimes = seed(manager, ['bad-close'], 'streamable', STALE);
    runtimes.get('bad-close')!.server.close.mockRejectedValue(new Error('already closed'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(1);
    expect(manager.getActiveSessionIds()).toEqual([]);
    expect(logged).toHaveBeenCalled();
    logged.mockRestore();
  });
});

describe('SessionManager session data', () => {
  it('answers from memory, with no store to consult', () => {
    const manager = new SessionManager();
    seed(manager, ['s1']);
    expect(manager.getSessionData('s1')?.projectId).toBe('proj_1');
    expect(manager.hasSession('s1')).toBe(true);
  });

  it('does not know a session it does not hold', () => {
    // There is nowhere else to look — which is exactly why the route above
    // answers 404 rather than trying to restore.
    const manager = new SessionManager();
    expect(manager.getSessionData('never')).toBeNull();
    expect(manager.hasSession('never')).toBe(false);
  });

  it('touch moves both clocks, and only one of them decides expiry', () => {
    const manager = new SessionManager();
    seed(manager, ['s1'], 'streamable', STALE);
    const before = manager.getSessionData('s1')!.lastAccessedAt;

    manager.touchSession('s1');

    expect(manager.getSessionData('s1')!.lastAccessedAt).toBeGreaterThan(before);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(monotonicNow() - (manager as any).runtimeSessions.get('s1').lastSeenAt)
      .toBeLessThan(SESSION_TTL_MS);
  });

  it('touching an unknown session is a no-op, not a throw', () => {
    const manager = new SessionManager();
    expect(() => manager.touchSession('never')).not.toThrow();
  });

  it('reports the same count twice, because there is one store', () => {
    // /health keeps both fields so a monitor reading it does not break, but
    // they can no longer disagree — the ratio between them is dead as a leak
    // signal, and memorySessionCount against heap replaces it.
    const manager = new SessionManager();
    seed(manager, ['a', 'b', 'c']);
    expect(manager.getStats()).toEqual({ activeSessions: 3, memorySessionCount: 3 });
  });
});

describe('SessionManager idle sweep timer', () => {
  it('starts once and stops cleanly', () => {
    vi.useFakeTimers();
    const manager = new SessionManager();
    const spy = vi.spyOn(manager, 'sweepOrphanedSessions').mockResolvedValue(0);

    manager.startIdleSweep(1000);
    manager.startIdleSweep(1000); // idempotent — must not add a second timer

    vi.advanceTimersByTime(3000);
    expect(spy).toHaveBeenCalledTimes(3);

    manager.stopIdleSweep();
    vi.advanceTimersByTime(5000);
    expect(spy).toHaveBeenCalledTimes(3);

    vi.useRealTimers();
  });

  it('survives a sweep that rejects', async () => {
    // This timer is now the only thing that expires a session, so it dying
    // quietly is a memory leak rather than a missed cleanup.
    vi.useFakeTimers();
    const manager = new SessionManager();
    const spy = vi.spyOn(manager, 'sweepOrphanedSessions').mockRejectedValue(new Error('boom'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    manager.startIdleSweep(1000);
    vi.advanceTimersByTime(1000);
    await Promise.resolve();
    expect(logged).toHaveBeenCalled();

    // And it keeps running afterwards.
    vi.advanceTimersByTime(1000);
    expect(spy).toHaveBeenCalledTimes(2);

    manager.stopIdleSweep();
    vi.useRealTimers();
    logged.mockRestore();
  });
});
