import { describe, it, expect, vi, beforeEach } from 'vitest';

const pipelineExec = vi.fn();
const pipelineExists = vi.fn();
const redisDel = vi.fn();

vi.mock('./redis.js', () => ({
  getRedisClient: () => ({
    pipeline: () => ({ exists: pipelineExists, exec: pipelineExec }),
    del: redisDel,
  }),
}));

const { SessionManager, selectOrphanedSessions } = await import('./session-manager.js');

/** Stand-in for a runtime entry; only close() is exercised by the sweep. */
function fakeRuntime(transportType: 'streamable' | 'sse' = 'streamable') {
  return {
    server: { close: vi.fn().mockResolvedValue(undefined) },
    transport: { close: vi.fn().mockResolvedValue(undefined) },
    transportType,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function seed(manager: any, ids: string[], transportType: 'streamable' | 'sse' = 'streamable') {
  const runtimes = new Map<string, ReturnType<typeof fakeRuntime>>();
  for (const id of ids) {
    const rt = fakeRuntime(transportType);
    runtimes.set(id, rt);
    manager.runtimeSessions.set(id, rt);
  }
  return runtimes;
}

describe('selectOrphanedSessions', () => {
  it('picks exactly the ids whose Redis record is gone', () => {
    expect(selectOrphanedSessions(['a', 'b', 'c'], [1, 0, 1])).toEqual(['b']);
  });

  it('treats a non-zero reply as alive', () => {
    expect(selectOrphanedSessions(['a', 'b'], [1, 1])).toEqual([]);
  });

  it('reaps nothing when every record is present', () => {
    expect(selectOrphanedSessions(['a'], [1])).toEqual([]);
  });
});

describe('SessionManager.sweepOrphanedSessions', () => {
  beforeEach(() => {
    pipelineExec.mockReset();
    pipelineExists.mockReset();
    redisDel.mockReset().mockResolvedValue(1);
  });

  it('is a no-op with nothing in memory', async () => {
    const manager = new SessionManager();
    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(pipelineExec).not.toHaveBeenCalled();
  });

  it('closes and drops only the sessions Redis has expired', async () => {
    const manager = new SessionManager();
    const runtimes = seed(manager, ['live', 'expired']);
    pipelineExec.mockResolvedValue([
      [null, 1],
      [null, 0],
    ]);

    const reaped = await manager.sweepOrphanedSessions();

    expect(reaped).toBe(1);
    expect(manager.getActiveSessionIds()).toEqual(['live']);
    expect(runtimes.get('expired')!.server.close).toHaveBeenCalled();
    expect(runtimes.get('expired')!.transport.close).toHaveBeenCalled();
    expect(runtimes.get('live')!.server.close).not.toHaveBeenCalled();
  });

  it('keeps every session when Redis errors, rather than reaping live ones', async () => {
    // A transient Redis failure must never be read as "these sessions are gone".
    const manager = new SessionManager();
    seed(manager, ['a', 'b']);
    pipelineExec.mockResolvedValue([
      [new Error('READONLY'), null],
      [new Error('READONLY'), null],
    ]);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toEqual(['a', 'b']);
  });

  it('keeps sessions when the pipeline returns nothing at all', async () => {
    const manager = new SessionManager();
    seed(manager, ['a']);
    pipelineExec.mockResolvedValue(null);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toEqual(['a']);
  });

  it('never reaps an SSE session, even with no Redis record', async () => {
    // SSE cleans up on res 'close' and nothing on its message path used to
    // refresh the record, so an SSE record lapses at TTL from creation while
    // the connection is still open and keepalive-warm. Sweeping it would drop
    // a live client.
    const manager = new SessionManager();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sse = seed(manager as any, ['sse-live'], 'sse');
    pipelineExec.mockResolvedValue([[null, 0]]);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(0);
    expect(manager.getActiveSessionIds()).toContain('sse-live');
    expect(sse.get('sse-live')!.transport.close).not.toHaveBeenCalled();
    // Nothing to ask Redis about, so no pipeline should have run at all.
    expect(pipelineExec).not.toHaveBeenCalled();
  });

  it('reaps an expired streamable session while leaving an SSE one alone', async () => {
    const manager = new SessionManager();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const streamable = seed(manager as any, ['http-dead'], 'streamable');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sse = seed(manager as any, ['sse-live'], 'sse');
    // Only the streamable id is queried, so a single reply is correct.
    pipelineExec.mockResolvedValue([[null, 0]]);

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(1);
    expect(manager.getActiveSessionIds()).toEqual(['sse-live']);
    expect(streamable.get('http-dead')!.transport.close).toHaveBeenCalled();
    expect(sse.get('sse-live')!.transport.close).not.toHaveBeenCalled();
  });

  it('reclaims an accumulation of orphans in one pass', async () => {
    // The production shape: many runtime sessions, few surviving Redis records.
    const manager = new SessionManager();
    const ids = Array.from({ length: 50 }, (_, i) => `s${i}`);
    seed(manager, ids);
    pipelineExec.mockResolvedValue(ids.map((_, i) => [null, i < 5 ? 1 : 0]));

    await expect(manager.sweepOrphanedSessions()).resolves.toBe(45);
    expect(manager.getActiveSessionIds()).toHaveLength(5);
  });
});

describe('SessionManager idle sweep timer', () => {
  beforeEach(() => {
    pipelineExec.mockReset().mockResolvedValue([]);
    pipelineExists.mockReset();
  });

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
    vi.useFakeTimers();
    const manager = new SessionManager();
    vi.spyOn(manager, 'sweepOrphanedSessions').mockRejectedValue(new Error('boom'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    manager.startIdleSweep(1000);
    vi.advanceTimersByTime(1000);
    await Promise.resolve();

    expect(logged).toHaveBeenCalled();
    manager.stopIdleSweep();
    vi.useRealTimers();
    logged.mockRestore();
  });
});
