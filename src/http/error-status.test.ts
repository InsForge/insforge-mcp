import { describe, expect, it } from 'vitest';
import { InsforgeApiError } from './insforge-api.js';
import { statusForHttpError, isAuthorizationRefusal, isUpstreamUnavailable } from './error-status.js';

describe('statusForHttpError', () => {
  it.each([400, 401, 403, 404, 409, 429])(
    'preserves an upstream %i client error',
    (status) => {
      expect(statusForHttpError(new InsforgeApiError('upstream rejected request', status)))
        .toBe(status);
    }
  );

  // The upstream-5xx rows moved out of this block deliberately: Iris measured
  // that reporting the platform's 500 as OUR 500 leaves a caller unable to tell
  // "the platform is down, retry" from "this server is broken, give up". They
  // are now 503 and live in the retryable-class block below.
  it.each([
    new Error('some failure with no upstream attribution'),
    'unknown failure',
  ])('keeps 500 for a failure we cannot attribute upstream', (error) => {
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

describe('statusForHttpError and the retryable class', () => {
  /**
   * Iris measured two failure shapes and got 500 for both — a DNS fast-fail and
   * a blackhole that hit the 10s timeout. A mapper with no 503 branch cannot
   * express "try again" however carefully its callers are written.
   */

  const withCause = (code: string) => Object.assign(new Error('fetch failed'), { cause: { code } });

  it('answers 503 when the platform did not answer at all', () => {
    expect(statusForHttpError(Object.assign(new Error('t'), { name: 'AbortError' }))).toBe(503);
    expect(statusForHttpError(Object.assign(new Error('t'), { name: 'TimeoutError' }))).toBe(503);
    expect(statusForHttpError(withCause('ENOTFOUND'))).toBe(503);
    expect(statusForHttpError(withCause('ECONNREFUSED'))).toBe(503);
    expect(statusForHttpError(withCause('ECONNRESET'))).toBe(503);
    expect(statusForHttpError(withCause('EHOSTUNREACH'))).toBe(503);
  });

  it('answers 503 when the platform answered 5xx or 429', () => {
    expect(statusForHttpError(new InsforgeApiError('boom', 500))).toBe(503);
    expect(statusForHttpError(new InsforgeApiError('gateway', 502))).toBe(503);
    // 429 passes through instead: more precise than "unavailable", and a
    // deliberate earlier decision the ordering in statusForHttpError preserves.
    expect(statusForHttpError(new InsforgeApiError('slow down', 429))).toBe(429);
  });

  it('still passes through the platform saying no', () => {
    // It looked and refused. Retrying does not help and the caller must not be
    // told it might.
    expect(statusForHttpError(new InsforgeApiError('nope', 401))).toBe(401);
    expect(statusForHttpError(new InsforgeApiError('nope', 403))).toBe(403);
    expect(statusForHttpError(new InsforgeApiError('gone', 404))).toBe(404);
  });

  it('keeps 500 for a failure we cannot attribute upstream', () => {
    // Most likely a bug in our own handler. Calling that temporary would tell a
    // client to keep hammering a broken server.
    expect(statusForHttpError(new TypeError('x is not a function'))).toBe(500);
    expect(statusForHttpError(new Error('something else'))).toBe(500);
    expect(statusForHttpError(undefined)).toBe(500);
  });

  it('does not confuse a refusal with an unavailability', () => {
    // The two classifiers must disagree on exactly the cases they are for.
    const refused = new InsforgeApiError('nope', 403);
    const stalled = Object.assign(new Error('t'), { name: 'AbortError' });
    expect(isAuthorizationRefusal(refused)).toBe(true);
    expect(isUpstreamUnavailable(refused)).toBe(false);
    expect(isAuthorizationRefusal(stalled)).toBe(false);
    expect(isUpstreamUnavailable(stalled)).toBe(true);
  });
});
