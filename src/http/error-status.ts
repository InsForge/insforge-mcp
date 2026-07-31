import { InsforgeApiError } from './insforge-api.js';

/**
 * Preserve client-error statuses returned by the InsForge API.
 *
 * Treat upstream 5xx responses and non-HTTP failures as server errors: those
 * are failures on our side of the MCP client's request and may be retryable.
 */
/**
 * Is this the platform refusing a credential, as opposed to us being unable to
 * ask it anything?
 *
 * The distinction that decides whether a caller is told "sign in again" or
 * "try again". 401 and 403 are the platform having looked and said no — the
 * grant is gone, revoked, or never covered this project. Everything else is
 * absence of an answer: a 500, a timeout, DNS, a rate limit, a socket reset.
 *
 * DEFAULTS TO FALSE, and that direction is deliberate. Treating an unknown
 * failure as a refusal signs a user out over a hiccup — costly, and it teaches
 * clients that reauthorization is the remedy for everything. Treating it as
 * unavailable returns a retryable error, which is recoverable without a human.
 * The expensive mistake is the one that touches the user.
 *
 * 429 is deliberately NOT a refusal. It is the platform declining to answer
 * right now, which is exactly the retryable case, and it arrives in the 4xx
 * range where a careless `>= 400 && < 500` test would swallow it.
 */
export function isAuthorizationRefusal(error: unknown): boolean {
  return (
    error instanceof InsforgeApiError && (error.statusCode === 401 || error.statusCode === 403)
  );
}

/**
 * Did the platform fail to answer, as opposed to answering "no"?
 *
 * The retryable class. A timeout aborts with an AbortError; a DNS failure, a
 * refused connection or a reset socket arrives as a plain Error from fetch;
 * an overloaded platform answers 5xx or 429. None of those are our caller's
 * fault and all of them may work on the next attempt.
 *
 * A plain unrecognised Error is deliberately NOT in here. That is most likely
 * a bug in our own handler, which retrying will not fix, and calling it
 * temporary would tell a client to keep hammering a broken server.
 */
export function isUpstreamUnavailable(error: unknown): boolean {
  if (error instanceof InsforgeApiError) {
    return error.statusCode >= 500 || error.statusCode === 429;
  }
  // AbortSignal.timeout aborts with an AbortError; older paths and undici use
  // TimeoutError. Both mean the same thing here.
  if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
    return true;
  }
  // Node surfaces connection failures as a cause with a code.
  const code = (error as { cause?: { code?: string } })?.cause?.code;
  return typeof code === 'string' && /^(ENOTFOUND|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|ETIMEDOUT|UND_ERR)/.test(code);
}

/**
 * The status to answer a caller with, given an upstream failure.
 *
 * THE 503 BRANCH IS THE ONE THAT WAS MISSING, and Iris found the hole by
 * measuring two failure shapes rather than one:
 *
 *   DNS fast-fail   500, instant
 *   blackhole IP    500, 10.9s    <- the timeout fires, the status does not change
 *
 * Both produced the same 500 as a genuine bug in our own code, so a caller
 * could not tell "the platform is down, try again" from "this server is
 * broken, give up" — the same confusion #95 fixed for a stale token and #97
 * fixed for revoke and resolve, arriving at the one place that maps everything
 * else. A mapper with no branch for the retryable case cannot express it
 * however carefully its callers are written.
 *
 * So: the platform's own 4xx answer passes through (it looked and said no),
 * anything that means it did not answer becomes 503, and only a failure we
 * cannot attribute upstream stays 500.
 */
export function statusForHttpError(error: unknown): number {
  // The platform's own 4xx passes through FIRST, and the order matters for
  // exactly one status: 429. It is retryable, so it would also satisfy the
  // check below — but "rate limited" is more precise than "unavailable" and a
  // caller can act on it differently. An earlier decision, deliberately kept.
  if (
    error instanceof InsforgeApiError &&
    error.statusCode >= 400 &&
    error.statusCode < 500
  ) {
    return error.statusCode;
  }

  if (isUpstreamUnavailable(error)) {
    return 503;
  }

  return 500;
}
