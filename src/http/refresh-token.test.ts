import { describe, it, expect } from 'vitest';
import {
  issueRefreshToken,
  readRefreshToken,
  REFRESH_TOKEN_TTL_SECONDS,
  MAX_REFRESH_TOKEN_LENGTH,
} from './refresh-token.js';
import { deriveRefreshTokenKey, deriveAccessTokenKey, deriveAuthStateKey } from './config.js';

const SECRET = 'a-platform-client-secret';
const KEY = deriveRefreshTokenKey(SECRET);

const PAYLOAD = {
  userId: 'user_123',
  platformRefreshToken: 'platform-refresh-abcdef',
  projectId: 'proj_456',
};

describe('the refresh token round trip', () => {
  it('carries the platform refresh token back out', () => {
    const token = issueRefreshToken(PAYLOAD, KEY);
    expect(readRefreshToken(token, KEY)).toEqual(PAYLOAD);
  });

  it('does not publish the platform credential to anyone holding it', () => {
    // Encrypted, not signed — the whole reason this envelope is not a JWT. A
    // readable refresh token would hand a month-long platform credential to
    // anything that logged the header it travels in.
    const token = issueRefreshToken(PAYLOAD, KEY);
    expect(token).not.toContain(PAYLOAD.platformRefreshToken);
    expect(Buffer.from(token, 'base64url').toString('utf8')).not.toContain(
      PAYLOAD.platformRefreshToken
    );
  });
});

describe('what must NOT open one', () => {
  it('refuses a token sealed under a different secret', () => {
    // The rotation case: INSFORGE_CLIENT_SECRET changes, every refresh token
    // issued under the old one stops opening. That is the intended revocation
    // and it is now five artifacts wide, not four.
    const token = issueRefreshToken(PAYLOAD, KEY);
    expect(readRefreshToken(token, deriveRefreshTokenKey('a-different-secret'))).toBeNull();
  });

  it.each([
    ['the access token key', deriveAccessTokenKey],
    ['the auth state key', deriveAuthStateKey],
  ])('refuses a token opened with %s from the SAME secret', (_label, derive) => {
    // The labels are the whole point of deriving five keys instead of using
    // one. Same secret, different label, no relationship — so an envelope
    // cannot be opened by the wrong consumer even inside one deployment.
    const token = issueRefreshToken(PAYLOAD, KEY);
    expect(readRefreshToken(token, derive(SECRET) as Buffer)).toBeNull();
  });

  it('refuses one that has expired', () => {
    const issuedAt = 1_700_000_000_000;
    const token = issueRefreshToken(PAYLOAD, KEY, issuedAt);
    const oneSecondLate = issuedAt + (REFRESH_TOKEN_TTL_SECONDS + 1) * 1000;
    expect(readRefreshToken(token, KEY, oneSecondLate)).toBeNull();
    // And is still good the moment before, so the boundary is the TTL rather
    // than something shorter that happens to pass.
    expect(readRefreshToken(token, KEY, issuedAt + (REFRESH_TOKEN_TTL_SECONDS - 1) * 1000)).toEqual(
      PAYLOAD
    );
  });

  it('refuses a string that is not one of ours at all', () => {
    expect(readRefreshToken('not-a-token', KEY)).toBeNull();
    expect(readRefreshToken('', KEY)).toBeNull();
  });
});

describe('the lifetime is the platform s, not ours', () => {
  it('is thirty days, matching REFRESH_TOKEN_EXPIRY on the platform', () => {
    // Not a preference. The platform's oauth service expires refresh tokens at
    // 30 * 24 * 3600; accepting ours for longer would advertise a life the
    // credential inside does not have — the same mismatch that had the access
    // token advertising 24h while dying in one.
    expect(REFRESH_TOKEN_TTL_SECONDS).toBe(30 * 24 * 3600);
  });
});

describe('the size bound', () => {
  it('issues a realistic token well inside the limit', () => {
    expect(issueRefreshToken(PAYLOAD, KEY).length).toBeLessThan(MAX_REFRESH_TOKEN_LENGTH);
  });

  it('refuses to issue one that is over it', () => {
    // The payload is ours, never the caller's, so this fires on a bug in us
    // rather than on a big request — which is why it throws instead of
    // returning an error the caller could act on.
    expect(() =>
      issueRefreshToken({ ...PAYLOAD, platformRefreshToken: 'x'.repeat(MAX_REFRESH_TOKEN_LENGTH) }, KEY)
    ).toThrow(/Refusing to issue a refresh token/);
  });
});
