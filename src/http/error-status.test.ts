import { describe, expect, it } from 'vitest';
import { InsforgeApiError } from './insforge-api.js';
import { statusForHttpError } from './error-status.js';

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
