import { z } from 'zod';
import fetch from 'node-fetch';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import { CreateBucketRequest, createBucketRequestSchema } from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';

export function registerStorageTools(ctx: RegisterContext): void {
  const { API_BASE_URL, registerTool, withUsageTracking, getApiKey, addBackgroundContext } = ctx;

  // --------------------------------------------------
  // STORAGE TOOLS
  // --------------------------------------------------

  registerTool(
    'create-bucket',
    'Create new storage bucket',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      ...createBucketRequestSchema.shape,
    },
    {
      title: 'Create Storage Bucket',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    withUsageTracking('create-bucket', async ({ apiKey, bucketName, isPublic }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/storage/buckets`, {
          method: 'POST',
          headers: {
            'x-api-key': actualApiKey,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ bucketName, isPublic } as CreateBucketRequest),
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage('Bucket created', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error creating bucket: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'list-buckets',
    'Lists all storage buckets',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
    },
    {
      title: 'List Storage Buckets',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    withUsageTracking('list-buckets', async ({ apiKey }) => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/storage/buckets`, {
          method: 'GET',
          headers: { 'x-api-key': getApiKey(apiKey) },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage('Buckets retrieved', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error listing buckets: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'delete-bucket',
    'Deletes a storage bucket',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      // Reuse the same bucket name validation as create-bucket
      bucketName: createBucketRequestSchema.shape.bucketName,
    },
    {
      title: 'Delete Storage Bucket',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    withUsageTracking('delete-bucket', async ({ apiKey, bucketName }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/storage/buckets/${encodeURIComponent(bucketName)}`, {
          method: 'DELETE',
          headers: { 'x-api-key': actualApiKey },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage('Bucket deleted', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error deleting bucket: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );
}
