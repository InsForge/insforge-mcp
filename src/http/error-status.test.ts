import { describe, expect, it } from 'vitest';
import { InsforgeApiError } from './insforge-api.js';
import { statusForHttpError, isAuthorizationRefusal } from './error-status.js';

describe('statusForHttpError', () => {
  it.each([400, 401, 403, 404, 409, 429])(
    'preserves an upstream %i client error',
    (status) => {
      expect(statusForHttpError(new InsforgeApiError('upstream rejected request', status)))
        .toBe(status);
    }
  );

  it.each([
    new InsforgeApiError('upstream unavailable', 500),
    new InsforgeApiError('upstream unavailable', 503),
    new Error('Redis failed'),
    'unknown failure',
  ])('maps non-client failures to 500', (error) => {
    expect(statusForHttpError(error)).toBe(500);
  });
});

describe('isAuthorizationRefusal', () => {
  /**
   * The rule Iris named: 401 when the credential is the problem, 5xx when we
   * could not tell. This function is the whole of "which one is it", so the
   * boundaries are pinned rather than left to a reader of the call site.
   */

  it('is a refusal for 401 and 403 — the platform looked and said no', () => {
    expect(isAuthorizationRefusal(new InsforgeApiError('nope', 401))).toBe(true);
    expect(isAuthorizationRefusal(new InsforgeApiError('nope', 403))).toBe(true);
  });

  it('is NOT a refusal for 5xx — that is absence of an answer', () => {
    // The case that made this function necessary. Treating it as a refusal
    // tells a user their sign-in died and sends them to a browser to fix a
    // platform blip that would have cleared on retry.
    expect(isAuthorizationRefusal(new InsforgeApiError('boom', 500))).toBe(false);
    expect(isAuthorizationRefusal(new InsforgeApiError('gateway', 502))).toBe(false);
    expect(isAuthorizationRefusal(new InsforgeApiError('down', 503))).toBe(false);
  });

  it('is NOT a refusal for 429, which sits in the 4xx range and is retryable', () => {
    // The one a careless `>= 400 && < 500` test would swallow. Rate limiting is
    // the platform declining to answer right now — precisely the retry case.
    expect(isAuthorizationRefusal(new InsforgeApiError('slow down', 429))).toBe(false);
  });

  it('is NOT a refusal for a network error, a timeout, or anything unrecognised', () => {
    // Defaults to false on purpose: the expensive mistake is the one that
    // signs a user out, so an unknown failure errs toward retryable.
    expect(isAuthorizationRefusal(new Error('ECONNRESET'))).toBe(false);
    expect(isAuthorizationRefusal(undefined)).toBe(false);
    expect(isAuthorizationRefusal({ statusCode: 401 })).toBe(false);
  });
});
