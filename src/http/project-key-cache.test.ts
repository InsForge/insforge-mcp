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

  it('does not leak entries once they expire', () => {
    // The binding leaked because nothing ever removed it. This one drops the
    // entry on the read that finds it stale.
    const c = new ProjectKeyCache();
    c.set('user_a', 'proj_1', value, T0);
    expect(c.size()).toBe(1);
    c.get('user_a', 'proj_1', T0 + PROJECT_KEY_TTL_MS);
    expect(c.size()).toBe(0);
  });
});
