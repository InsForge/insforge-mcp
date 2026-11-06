import { describe, it, expect } from 'vitest';
import {
  createBucketRequestSchema,
  createDeploymentResponseSchema,
  createDirectDeploymentResponseSchema,
  deploymentManifestFileEntrySchema,
  startDeploymentRequestSchema,
  uploadFunctionRequestSchema,
} from './schemas.js';

// These schemas were ported from @insforge/shared-schemas (zod 3) to zod 4.
// Each case pins a zod 3 behaviour that a naive port would change.

const sha = 'a'.repeat(40);

describe('zod 4 schema port keeps shared-schemas semantics', () => {
  it('accepts any 8-4-4-4-12 hex id, like zod 3 uuid()', () => {
    // Version nibble 0 and variant nibble 0 fail zod 4's RFC 9562 z.uuid().
    const id = '123e4567-e89b-02d3-0456-426614174000';
    expect(
      createDeploymentResponseSchema.safeParse({
        id,
        uploadUrl: 'https://s3.amazonaws.com/bucket',
        uploadFields: {},
      }).success
    ).toBe(true);
    expect(
      createDeploymentResponseSchema.safeParse({
        id: 'not-a-uuid',
        uploadUrl: 'https://s3.amazonaws.com/bucket',
        uploadFields: {},
      }).success
    ).toBe(false);
  });

  it('checks record values, not only keys', () => {
    const base = { id: '123e4567-e89b-12d3-a456-426614174000', uploadUrl: 'https://x.test/' };
    expect(
      createDeploymentResponseSchema.safeParse({ ...base, uploadFields: { k: 1 } }).success
    ).toBe(false);
    expect(startDeploymentRequestSchema.safeParse({ meta: { k: 1 } }).success).toBe(false);
    expect(startDeploymentRequestSchema.safeParse({ meta: { k: 'v' } }).success).toBe(true);
  });

  it('rejects unsafe manifest paths', () => {
    for (const path of ['', '/abs', 'a\\b', 'a//b', './a', 'a/../b', 'a\0b', 'x'.repeat(2049)]) {
      expect(
        deploymentManifestFileEntrySchema.safeParse({ path, sha, size: 1 }).success,
        path
      ).toBe(false);
    }
    expect(
      deploymentManifestFileEntrySchema.safeParse({ path: 'a/b.js', sha, size: 0 }).success
    ).toBe(true);
  });

  it('rejects a bad manifest sha or size', () => {
    expect(
      deploymentManifestFileEntrySchema.safeParse({ path: 'a', sha: 'g'.repeat(40), size: 1 })
        .success
    ).toBe(false);
    expect(deploymentManifestFileEntrySchema.safeParse({ path: 'a', sha, size: -1 }).success).toBe(
      false
    );
    expect(deploymentManifestFileEntrySchema.safeParse({ path: 'a', sha, size: 1.5 }).success).toBe(
      false
    );
  });

  it('rejects an unknown direct deployment status', () => {
    const base = { id: '123e4567-e89b-12d3-a456-426614174000', files: [] };
    expect(
      createDirectDeploymentResponseSchema.safeParse({ ...base, status: 'WAITING' }).success
    ).toBe(true);
    expect(
      createDirectDeploymentResponseSchema.safeParse({ ...base, status: 'DONE' }).success
    ).toBe(false);
  });

  it('applies defaults', () => {
    expect(createBucketRequestSchema.parse({ bucketName: 'b' })).toEqual({
      bucketName: 'b',
      isPublic: true,
    });
    expect(uploadFunctionRequestSchema.parse({ name: 'n', code: 'c' }).status).toBe('active');
  });

  it('keeps custom error messages', () => {
    const result = uploadFunctionRequestSchema.safeParse({
      name: 'n',
      code: 'c',
      slug: 'bad slug',
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0].message).toBe(
      'Invalid slug format - must be alphanumeric with hyphens or underscores only'
    );
  });
});
