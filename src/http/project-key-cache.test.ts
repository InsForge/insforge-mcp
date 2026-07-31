import { describe, it, expect } from 'vitest';
import { ProjectKeyCache, PROJECT_KEY_TTL_MS } from './project-key-cache.js';

const value = {
  apiKey: 'ik_secret',
  accessHost: 'https://p.insforge.app',
  projectName: 'demo',
  organizationId: 'org_1',
};
const T0 = 1_700_000_000_000;

describe('the project key cache', () => {
  it('returns what was put in, within the TTL', () => {
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.get('user_a', 'proj_1', T0)).toEqual(value);
    expect(c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS - 1)).toEqual(value);
  });

  it('expires exactly at the TTL, so revocation cannot be stale for longer', () => {
    // The number that keeps the platform's revoke meaningful. Caching bounded
    // by the token's own exp — which is what I first specced — would make
    // revoke a no-op from our side for the life of the token.
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS)).toBeUndefined();
    expect(PROJECT_KEY_TTL_MS).toBe(60_000);
  });

  it('never serves one user the key another user got for the same project', () => {
    // Two users can both reach a project with different grants. A cache keyed
    // on the project alone would be a cross-tenant bug.
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.get('user_b', 'proj_1', T0)).toBeUndefined();
  });

  it('keeps projects apart for one user', () => {
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.get('user_a', 'proj_2', T0)).toBeUndefined();
  });

  it('forgets one user without touching another', () => {
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    c.set('user_b', 'proj_1', value, T0);
    c.forgetUser('user_a');
    expect(c.get('user_a', 'proj_1', T0)).toBeUndefined();
    expect(c.get('user_b', 'proj_1', T0)).toEqual(value);
  });

  it('drops an entry on the read that finds it stale', () => {
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.size()).toBe(1);
    c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS);
    expect(c.size()).toBe(0);
  });

  it('evicts entries NOBODY reads again — the leak Quinn measured', () => {
    // The original checked expiry on read only, and its comment claimed an
    // unread entry cost a slot "for 60 seconds". Measured, it cost one
    // forever: 10,000 written, one more an hour later, nothing re-read, size
    // 10,001 — each holding a project API key well past the TTL that exists to
    // bound exactly that.
    const c = new ProjectKeyCache();
    for (let i = 0; i < 10_000; i++) c.set(`user_${i}`, 'proj', value, T0);
    expect(c.size()).toBe(10_000);

    c.set('someone', 'else', value, T0 + 60 * PROJECT_KEY_TTL_MS);
    expect(c.size()).toBe(1);
  });

  it('scans at most once a second, and the read path covers the gap', () => {
    // Eviction is O(n) on a per-request path, so it is rate-limited rather than
    // run on every write. This pins the amortisation — and, more importantly,
    // that a still-resident expired entry is NEVER SERVED: correctness lives on
    // the read path, tidiness on the write path.
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0); // scans; a expires at T0 + TTL
    c.set('user_b', 'proj_1', value, T0 + PROJECT_KEY_TTL_MS - 500); // scans; a still fresh

    // 501ms after that scan: inside the interval, so no scan runs and user_a's
    // expired entry is still resident.
    c.set('user_c', 'proj_1', value, T0 + PROJECT_KEY_TTL_MS + 1);
    expect(c.size()).toBe(3);

    // ...but it cannot be read.
    expect(c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS + 1)).toBeUndefined();
  });

  it('cannot confuse two (user, project) pairs that join to the same string', () => {
    // `${userId} ${projectId}` made these one entry:
    //   ('a', 'b c')  and  ('a b', 'c')  both -> "a b c"
    // Unreachable while both are platform UUIDs, and a live cross-tenant bug
    // the moment project_id becomes a caller-supplied tool argument. Nesting
    // the maps makes it unrepresentable rather than merely unlikely.
    const first = { ...value, apiKey: 'ik_first' };
    const second = { ...value, apiKey: 'ik_second' };
    const c = new ProjectKeyCache();

    c.set('a', 'b c', first, T0);
    c.set('a b', 'c', second, T0);

    expect(c.get('a', 'b c', T0)).toEqual(first);
    expect(c.get('a b', 'c', T0)).toEqual(second);
    expect(c.size()).toBe(2);
  });

  it('forgets a user without forgetting one whose id is a prefix of theirs', () => {
    // forgetUser was a prefix scan over joined keys, carrying the same
    // assumption. A structural key makes the question not arise.
    const c = new ProjectKeyCache();
    c.set('user', 'proj_1', value, T0);
    c.set('user_extended', 'proj_1', value, T0);

    c.forgetUser('user');

    expect(c.get('user', 'proj_1', T0)).toBeUndefined();
    expect(c.get('user_extended', 'proj_1', T0)).toEqual(value);
  });

  it('leaves no empty shell behind for a user whose entries are all gone', () => {
    // The nesting adds a container per user; if those were never removed the
    // leak would simply move up a level.
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS);
    expect(c.size()).toBe(0);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any).byUser.size).toBe(0);
  });
});
