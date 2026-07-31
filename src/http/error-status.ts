import { InsforgeApiError } from './insforge-api.js';

/**
 * Preserve client-error statuses returned by the InsForge API.
 *
 * Treat upstream 5xx responses and non-HTTP failures as server errors: those
 * are failures on our side of the MCP client's request and may be retryable.
 */
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
