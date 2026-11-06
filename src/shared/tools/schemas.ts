import { z } from 'zod';

/**
 * Zod 4 schemas for the tool inputs and backend payloads this server validates.
 *
 * Ported from @insforge/shared-schemas@1.1.49, which is built on zod 3. Mixing
 * its schemas with this package's zod 4 schemas in one tool shape makes the MCP
 * SDK throw "Mixed Zod versions detected in object shape", and its zod 3 type
 * declarations resolve to `any` under zod 4. Keep these in step with the
 * backend contract; switch back to shared-schemas once it ships on zod >= 4.6.6.
 *
 * `z.guid()` keeps zod 3's permissive `uuid()` pattern; zod 4's `z.uuid()`
 * additionally enforces RFC 9562 version/variant bits.
 */

// docs.schema
export const docTypeSchema = z.enum([
  'instructions',
  'auth-sdk',
  'db-sdk',
  'storage-sdk',
  'functions-sdk',
  'ai-integration-sdk',
  'real-time',
  'deployment',
]).describe(`
    Documentation type:
      "instructions" (essential backend setup - use FIRST),
      "db-sdk" (database operations),
      "storage-sdk" (file storage),
      "functions-sdk" (edge functions),
      "auth-sdk" (direct SDK methods for custom auth flows),
      "ai-integration-sdk" (AI features),
      "real-time" (real-time pub/sub through WebSockets),
      "deployment" (deploy frontend applications via MCP tool)
    `);

export const sdkFeatureSchema = z.enum(['db', 'storage', 'functions', 'auth', 'ai', 'realtime'])
  .describe(`
    SDK feature categories:

    - "db" - Database operations
    - "storage" - File storage
    - "functions" - Edge functions
    - "auth" - User authentication
    - "ai" - AI features
    - "realtime" - Real-time WebSockets
    `);

export const sdkLanguageSchema = z.enum([
  'typescript',
  'swift',
  'kotlin',
  // 'flutter',
  'rest-api',
]).describe(`
    SDK languages:

    - "typescript" - JavaScript/TypeScript SDK
    - "swift" - Swift SDK
    - "kotlin" - Kotlin SDK
    - "rest-api" - REST API
    `);

// storage-api.schema
export const createBucketRequestSchema = z.object({
  bucketName: z.string().min(1, 'Bucket name cannot be empty'),
  isPublic: z.boolean().default(true),
});
export type CreateBucketRequest = z.infer<typeof createBucketRequestSchema>;

// database-api.schema
export const rawSQLRequestSchema = z.object({
  query: z.string().min(1, 'Query is required'),
  params: z.array(z.unknown()).optional(),
});
export type RawSQLRequest = z.infer<typeof rawSQLRequestSchema>;

export const bulkUpsertRequestSchema = z.object({
  table: z.string().min(1, 'Table name is required'),
  upsertKey: z.string().optional(),
  // Note: File handling is done at the API layer via multipart/form-data
});

// functions.schema / functions-api.schema
export const functionSchema = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  code: z.string(),
  status: z.enum(['draft', 'active', 'error']),
  createdAt: z.string(),
  updatedAt: z.string(),
  deployedAt: z.string().nullable(),
});

export const uploadFunctionRequestSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  slug: z
    .string()
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Invalid slug format - must be alphanumeric with hyphens or underscores only'
    )
    .optional(),
  code: z.string().min(1),
  description: z.string().optional(),
  status: z.enum(['draft', 'active']).optional().default('active'),
});

export const updateFunctionRequestSchema = z.object({
  name: z.string().optional(),
  code: z.string().optional(),
  description: z.string().optional(),
  status: z.enum(['draft', 'active']).optional(),
});
export type UpdateFunctionRequest = z.infer<typeof updateFunctionRequestSchema>;

// deployments.schema / deployments-api.schema
export const deploymentStatusSchema = z.enum([
  'WAITING',
  'UPLOADING',
  'QUEUED',
  'BUILDING',
  'READY',
  'ERROR',
  'CANCELED',
]);

export const projectSettingsSchema = z.object({
  buildCommand: z.string().nullable().optional(),
  outputDirectory: z.string().nullable().optional(),
  installCommand: z.string().nullable().optional(),
  devCommand: z.string().nullable().optional(),
  rootDirectory: z.string().nullable().optional(),
});

export const envVarSchema = z.object({
  key: z.string(),
  value: z.string(),
});

export const deploymentFilePathSchema = z
  .string()
  .min(1, 'path is required')
  .max(2048, 'path is too long')
  .refine((value) => !value.includes('\0'), 'path cannot contain null bytes')
  .refine((value) => !value.includes('\\'), 'path must use forward slashes')
  .refine((value) => !value.startsWith('/'), 'path must be relative')
  .refine(
    (value) => value.split('/').every((part) => part !== '' && part !== '.' && part !== '..'),
    'path cannot contain empty, current, or parent directory segments'
  );

export const deploymentManifestFileEntrySchema = z.object({
  path: deploymentFilePathSchema,
  sha: z.string().regex(/^[a-f0-9]{40}$/i, 'sha must be a SHA-1 hex digest'),
  size: z.number().int().nonnegative(),
});
export type DeploymentManifestFileEntry = z.infer<typeof deploymentManifestFileEntrySchema>;

export const deploymentManifestFileSchema = deploymentManifestFileEntrySchema.extend({
  fileId: z.guid(),
  uploadedAt: z.iso.datetime().nullable(),
});
export type DeploymentManifestFile = z.infer<typeof deploymentManifestFileSchema>;

export const createDeploymentResponseSchema = z.object({
  id: z.guid(),
  uploadUrl: z.url(),
  uploadFields: z.record(z.string(), z.string()),
});
export type CreateDeploymentResponse = z.infer<typeof createDeploymentResponseSchema>;

export const createDirectDeploymentResponseSchema = z.object({
  id: z.guid(),
  status: deploymentStatusSchema,
  files: z.array(deploymentManifestFileSchema),
});
export type CreateDirectDeploymentResponse = z.infer<typeof createDirectDeploymentResponseSchema>;

export const startDeploymentRequestSchema = z.object({
  projectSettings: projectSettingsSchema.optional(),
  envVars: z.array(envVarSchema).optional(),
  meta: z.record(z.string(), z.string()).optional(),
});
export type StartDeploymentRequest = z.infer<typeof startDeploymentRequestSchema>;
