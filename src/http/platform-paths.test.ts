import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * The check that would have caught the revoke bug, and the one nothing had.
 *
 * `revokePlatformToken` called `/oauth/v1/revoke`. The platform serves that at
 * `/api/oauth/v1/revoke` and answers 404 at the other, so revoke would have
 * failed every time in production — while passing every test, because the stub
 * matched `url.includes('/oauth/v1/revoke')`, which is true of both. Nothing
 * else could catch it either: the reachable production probes
 * (not-our-token -> 200) return before the upstream call, and CI never touches
 * the platform.
 *
 * Iris proposed a live probe against api.insforge.dev. That verifies more than
 * this does — it confirms the constants are CORRECT, not merely consistent —
 * and it is worth having. But it couples CI to the platform being reachable,
 * which makes a green build depend on someone else's uptime. This is the half
 * that needs no network and no uptime, so it can run on every push:
 *
 *   the platform has two path families, and every URL must come from the
 *   constant that names its family rather than from a hand-typed prefix.
 *
 * That is exactly the mistake that was made. `${INSFORGE_API_BASE}/oauth/...`
 * type-checks, reads correctly, and is wrong.
 */

const source = readFileSync(join(__dirname, 'insforge-api.ts'), 'utf8');

/** Every template-literal URL passed to platformFetch. */
function platformUrls(): string[] {
  return [...source.matchAll(/platformFetch\(\s*`([^`]+)`/g)].map((m) => m[1]);
}

describe('platform URL construction', () => {
  it('finds the calls at all, so this test cannot pass by matching nothing', () => {
    // The meta-check. A regex that silently stops matching turns this file into
    // a green light that asserts nothing — the same vacuous-check trap as a
    // ratio that can never disagree.
    expect(platformUrls().length).toBeGreaterThanOrEqual(7);
  });

  it('builds every OAuth URL from OAUTH_API_BASE, never by hand', () => {
    // `${INSFORGE_API_BASE}/oauth/v1/revoke` is a 404 on the real platform.
    // It compiles, it reads correctly, and it is wrong.
    const handBuiltOAuth = platformUrls().filter(
      (u) => /oauth/i.test(u) && !u.startsWith('${OAUTH_API_BASE}')
    );
    expect(handBuiltOAuth).toEqual([]);
  });

  it('builds every non-OAuth URL from INSFORGE_API_BASE at the root', () => {
    // The other family: /auth/v1, /organizations/v1, /projects/v1 — all at the
    // root, and all 404 under /api. Measured, not assumed.
    const wrong = platformUrls().filter(
      (u) => !/oauth/i.test(u) && !u.startsWith('${INSFORGE_API_BASE}/')
    );
    expect(wrong).toEqual([]);
  });

  it('never puts an /api prefix on a root-family URL', () => {
    // /api/auth/v1/profile is a 404. This is the inverse of the revoke bug and
    // just as invisible to a reader.
    const prefixed = platformUrls().filter((u) => u.startsWith('${INSFORGE_API_BASE}/api/'));
    expect(prefixed).toEqual([]);
  });

  it('routes every outbound platform call through platformFetch', () => {
    // The timeout lives in that wrapper, so a bare `fetch(` here is a call with
    // no bound — which is how the callback exchange sat unclassified in
    // server.ts until it was moved into this file.
    //
    // EXACTLY ONE is correct: platformFetch's own call, the line that applies
    // the AbortSignal. A second one is someone adding a platform call that
    // skips the timeout, which is the failure this asserts against — and if
    // this ever reads 0, the wrapper itself has been refactored away and the
    // bound with it.
    const bare = [...source.matchAll(/(?<!platformF|F)etch\(/g)]
      .length;
    expect(bare, 'expected only platformFetch to call fetch directly').toBe(1);
  });
});

/**
 * A property that only became load-bearing when the binding landed.
 *
 * #99 exempts `initialize` from the credential check so a re-authorized client
 * can recover. That is safe for exactly one reason: the session id created by
 * the create path is generated, never taken from the request. If it were ever
 * derived from the incoming `Mcp-Session-Id`, an attacker holding their own
 * valid credentials could initialize ONTO a victim's session id, overwrite the
 * entry in the session map and take the session over — the exemption handing
 * them the very thing the binding prevents.
 *
 * Quinn measured it closed (asked for 11111111-…, got a server-generated id).
 * This pins it, because "we happen to generate it" is not a property anyone
 * would notice losing in review.
 */
describe('the create path never adopts a caller-supplied session id', () => {
  const server = readFileSync(join(__dirname, 'server.ts'), 'utf8');

  it('generates the new session id with randomUUID', () => {
    expect(server).toMatch(/const newSessionId = randomUUID\(\);/);
  });

  it('feeds the transport that generated id and nothing from the request', () => {
    const generators = [...server.matchAll(/sessionIdGenerator:\s*([^,\n]+)/g)].map((m) => m[1].trim());
    // The meta-check: if this stops matching, the assertion below is vacuous.
    expect(generators.length).toBeGreaterThanOrEqual(1);
    // `() => sessionId` — the request's id — is the mutation this forbids.
    expect(generators).toEqual(generators.map(() => '() => newSessionId'));
  });
});
