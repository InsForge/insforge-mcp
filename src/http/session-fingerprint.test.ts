import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { sessionFingerprint } from './session-manager.js';

describe('sessionFingerprint', () => {
  it('is stable, so a support report still correlates', () => {
    const id = 'e6b1d2c4-9f3a-4c77-9c1e-6d5a0f2b1a33';
    expect(sessionFingerprint(id)).toBe(sessionFingerprint(id));
  });

  it('does not reveal the id it summarises', () => {
    const id = 'e6b1d2c4-9f3a-4c77-9c1e-6d5a0f2b1a33';
    const fp = sessionFingerprint(id);
    expect(fp).toHaveLength(8);
    expect(id).not.toContain(fp);
    expect(sessionFingerprint('e6b1d2c4-9f3a-4c77-9c1e-6d5a0f2b1a34')).not.toBe(fp);
  });

  it('says "none" rather than "undefined" for a request without one', () => {
    expect(sessionFingerprint(undefined)).toBe('none');
    expect(sessionFingerprint(null)).toBe('none');
    expect(sessionFingerprint('')).toBe('none');
  });
});

/**
 * The guard that matters.
 *
 * The bug was never one wrong line — it was that a session id reaches a log
 * through three different expression shapes, in two files, and a reviewer
 * checking one shape sees a clean diff. A runtime grep has the same blind spot
 * from the other side: it only covers the paths the test happened to exercise,
 * so the SSE cluster stays invisible unless someone opens an SSE session.
 *
 * So this reads the source instead of the behaviour: no console line in either
 * file may pass a session id through anything but sessionFingerprint. It fails
 * on a shape nobody has thought of yet, which is the failure mode the last two
 * rounds of this had.
 */
describe('no console line prints a raw session id', () => {
  const files = ['server.ts', 'session-manager.ts'];

  // `${sessionId}`, `${transport.sessionId}`, and a positional `, sessionId)`.
  const RAW = /\$\{\s*(?:transport\.)?(?:sessionId|newSessionId|initializedSessionId)\s*(?:\|\||\})|,\s*(?:transport\.)?(?:sessionId|newSessionId|initializedSessionId)\s*\)/;

  for (const name of files) {
    it(`${name} has none`, () => {
      const src = readFileSync(join(__dirname, name), 'utf8');
      const offenders = src
        .split('\n')
        .map((line, i) => ({ line: line.trim(), n: i + 1 }))
        .filter(({ line }) => /console\.(log|error|warn|info)/.test(line))
        .filter(({ line }) => RAW.test(line))
        .map(({ line, n }) => `${name}:${n}  ${line.slice(0, 100)}`);

      expect(offenders).toEqual([]);
    });
  }

  it('the scan is not vacuous — it sees a raw id when there is one', () => {
    const sample = "console.log(`[Streamable HTTP] Session ${sessionId} closed`);";
    expect(RAW.test(sample)).toBe(true);
    const positional = "console.log('[Streamable HTTP] New session created:', newSessionId);";
    expect(RAW.test(positional)).toBe(true);
    const sse = 'console.log(`[SSE] Session closed: ${transport.sessionId}`);';
    expect(RAW.test(sse)).toBe(true);
    const fingerprinted = 'console.log(`[SSE] Session closed: ${sessionFingerprint(transport.sessionId)}`);';
    expect(RAW.test(fingerprinted)).toBe(false);
  });
});
