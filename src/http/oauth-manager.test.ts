import { describe, it, expect, vi, beforeEach } from 'vitest';

const redisGet = vi.fn();
const redisSetex = vi.fn();
const redisExpire = vi.fn();

vi.mock('./redis.js', () => ({
  getRedisClient: () => ({ get: redisGet, setex: redisSetex, expire: redisExpire }),
}));

// The manager pulls in the whole platform API surface at import time; none of
// it is on touchBinding's path.
vi.mock('./insforge-api.js', () => ({
  validateToken: vi.fn(),
  getProjectAccess: vi.fn(),
  getAllUserProjects: vi.fn(),
  InsforgeApiError: class extends Error {},
}));

const { getOAuthManager, CLIENT_REGISTRATION_PREFIX, CLIENT_REGISTRATION_TTL } = await import(
  './oauth-manager.js'
);

const TOKEN_HASH = 'a'.repeat(64);

function binding(extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    tokenHash: TOKEN_HASH,
    userId: 'u1',
    userEmail: 'user@example.com',
    projectId: 'p1',
    projectName: 'Project',
    organizationId: 'o1',
    accessHost: 'https://p1.example.com',
    apiKey: 'ik_test',
    createdAt: 1,
    lastUsedAt: 1,
    ...extra,
  });
}

describe('OAuthManager.touchBinding', () => {
  beforeEach(() => {
    redisGet.mockReset();
    redisSetex.mockReset().mockResolvedValue('OK');
    redisExpire.mockReset().mockResolvedValue(1);
  });

  it('slides the client registration on the same beat as the binding', async () => {
    // The whole point: a binding renews on every authenticated request, but the
    // registration behind it only renewed at /oauth/authorize — which an
    // ordinary user never returns to after signing in once.
    redisGet.mockResolvedValue(binding({ clientId: 'mcp_abc' }));

    await getOAuthManager().touchBinding(TOKEN_HASH);

    expect(redisSetex).toHaveBeenCalled();
    expect(redisExpire).toHaveBeenCalledWith(
      CLIENT_REGISTRATION_PREFIX + 'mcp_abc',
      CLIENT_REGISTRATION_TTL
    );
  });

  it('leaves the registration alone for a binding with no clientId', async () => {
    // Every binding written before this field existed, plus the direct bind
    // API, where there is no registered OAuth client at all.
    redisGet.mockResolvedValue(binding());

    await getOAuthManager().touchBinding(TOKEN_HASH);

    expect(redisSetex).toHaveBeenCalled();
    expect(redisExpire).not.toHaveBeenCalled();
  });

  it('does not fail the request when the registration refresh throws', async () => {
    // A TTL refresh is housekeeping. Losing it costs the registration its
    // extension, not the user their request.
    redisGet.mockResolvedValue(binding({ clientId: 'mcp_abc' }));
    redisExpire.mockRejectedValue(new Error('READONLY'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(getOAuthManager().touchBinding(TOKEN_HASH)).resolves.toBeUndefined();

    expect(redisSetex).toHaveBeenCalled();
    expect(logged).toHaveBeenCalled();
    logged.mockRestore();
  });

  it('touches nothing at all when the binding is gone', async () => {
    redisGet.mockResolvedValue(null);

    await getOAuthManager().touchBinding(TOKEN_HASH);

    expect(redisSetex).not.toHaveBeenCalled();
    expect(redisExpire).not.toHaveBeenCalled();
  });
});
