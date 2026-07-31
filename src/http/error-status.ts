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

export function statusForHttpError(error: unknown): number {
  if (
    error instanceof InsforgeApiError &&
    error.statusCode >= 400 &&
    error.statusCode < 500
  ) {
    return error.statusCode;
  }

  return 500;
}
