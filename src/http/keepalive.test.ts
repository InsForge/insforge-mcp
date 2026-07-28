import { describe, it, expect, vi, afterEach, type Mock } from 'vitest';
import { positiveIntEnv } from './config.js';

/**
 * The keepalive itself is a few lines inline in the SSE handler, and server.ts
 * calls startServer() at import time so it can't be imported here. These cover
 * the behaviour that matters — write on tick, stop on close, never write to a
 * finished response — against the same shape the handler uses, plus the env
 * parsing that decides the interval.
 */

type FakeRes = {
  writableEnded: boolean;
  write: Mock<(chunk: string) => void>;
  handlers: Record<string, () => void>;
  on: (event: string, fn: () => void) => void;
  emit: (event: string) => void;
};

function fakeRes(): FakeRes {
  const res: FakeRes = {
    writableEnded: false,
    write: vi.fn<(chunk: string) => void>(),
    handlers: {},
    on(event, fn) {
      res.handlers[event] = fn;
    },
    emit(event) {
      res.handlers[event]?.();
    },
  };
  return res;
}

/** Mirrors the handler: start an interval, clear it when the response closes. */
function attachKeepAlive(res: FakeRes, intervalMs: number) {
  const timer = setInterval(() => {
    if (res.writableEnded) return;
    try {
      res.write(': keepalive\n\n');
    } catch {
      /* handler logs; irrelevant here */
    }
  }, intervalMs);
  timer.unref?.();
  res.on('close', () => clearInterval(timer));
  return timer;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('SSE keepalive', () => {
  it('writes a comment frame on each tick', () => {
    vi.useFakeTimers();
    const res = fakeRes();
    attachKeepAlive(res, 1000);

    vi.advanceTimersByTime(3000);

    expect(res.write).toHaveBeenCalledTimes(3);
    // A comment frame: ignored by the event-stream parser, so it cannot be
    // mistaken for protocol traffic by a client.
    expect(res.write).toHaveBeenCalledWith(': keepalive\n\n');
  });

  it('stops writing once the response closes', () => {
    vi.useFakeTimers();
    const res = fakeRes();
    attachKeepAlive(res, 1000);

    vi.advanceTimersByTime(2000);
    expect(res.write).toHaveBeenCalledTimes(2);

    res.emit('close');
    vi.advanceTimersByTime(10000);

    expect(res.write).toHaveBeenCalledTimes(2);
  });

  it('does not write to a response that has already ended', () => {
    vi.useFakeTimers();
    const res = fakeRes();
    attachKeepAlive(res, 1000);

    res.writableEnded = true;
    vi.advanceTimersByTime(5000);

    expect(res.write).not.toHaveBeenCalled();
  });

  it('keeps ticking when a write throws', () => {
    vi.useFakeTimers();
    const res = fakeRes();
    res.write.mockImplementation(() => {
      throw new Error('EPIPE');
    });
    attachKeepAlive(res, 1000);

    expect(() => vi.advanceTimersByTime(3000)).not.toThrow();
    expect(res.write).toHaveBeenCalledTimes(3);
  });
});

describe('positiveIntEnv', () => {
  it('uses the fallback when unset', () => {
    expect(positiveIntEnv(undefined, 25_000)).toBe(25_000);
  });

  it('accepts a positive override', () => {
    expect(positiveIntEnv('1500', 25_000)).toBe(1500);
  });

  it.each(['-1', '0', 'abc', '', '  '])(
    'falls back for %j rather than passing it to setInterval',
    (value) => {
      // setInterval clamps a non-positive delay to 1ms, which would spin
      // writing keepalive frames as fast as the event loop allows.
      expect(positiveIntEnv(value, 25_000)).toBe(25_000);
    }
  );

  it('ignores trailing junk the way parseInt does, but still demands a number', () => {
    expect(positiveIntEnv('1500ms', 25_000)).toBe(1500);
    expect(positiveIntEnv('ms1500', 25_000)).toBe(25_000);
  });
});
