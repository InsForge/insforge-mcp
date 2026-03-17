import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import {
  UpdateFunctionRequest,
  updateFunctionRequestSchema,
  uploadFunctionRequestSchema,
  functionSchema,
} from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';

export function registerFunctionTools(ctx: RegisterContext): void {
  const { API_BASE_URL, isRemote, registerTool, withUsageTracking, getApiKey, addBackgroundContext } = ctx;

  // --------------------------------------------------
  // EDGE FUNCTION TOOLS
  // --------------------------------------------------

  if (isRemote) {
    // Remote mode: accept inline code string directly
    registerTool(
      'create-function',
      'Create a new edge function that runs in Deno runtime',
      {
        apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
        ...uploadFunctionRequestSchema.omit({ code: true }).shape,
        code: z.string().describe(
          'The function code as a string. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      withUsageTracking('create-function', async (args: any) => {
        try {
          const response = await fetch(`${API_BASE_URL}/api/functions`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': getApiKey(args.apiKey),
            },
            body: JSON.stringify({
              slug: args.slug,
              name: args.name,
              code: args.code,
              description: args.description,
              status: args.status,
            }),
          });

          const result = await handleApiResponse(response);
          return await addBackgroundContext({
            content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' created successfully`, result) }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error creating function: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  } else {
    // Local mode: read code from local file path
    registerTool(
      'create-function',
      'Create a new edge function that runs in Deno runtime. The code must be written to a file first for version control',
      {
        apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
        ...uploadFunctionRequestSchema.omit({ code: true }).shape,
        codeFile: z.string().describe(
          'Path to JavaScript file containing the function code. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      withUsageTracking('create-function', async (args: any) => {
        try {
          let code: string;
          try {
            code = await fs.readFile(args.codeFile, 'utf-8');
          } catch (fileError) {
            throw new Error(
              `Failed to read code file '${args.codeFile}': ${fileError instanceof Error ? fileError.message : 'Unknown error'}`,
              { cause: fileError }
            );
          }

          const response = await fetch(`${API_BASE_URL}/api/functions`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': getApiKey(args.apiKey),
            },
            body: JSON.stringify({
              slug: args.slug,
              name: args.name,
              code,
              description: args.description,
              status: args.status,
            }),
          });

          const result = await handleApiResponse(response);
          return await addBackgroundContext({
            content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' created successfully from ${args.codeFile}`, result) }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error creating function: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  }

  registerTool(
    'get-function',
    'Get details of a specific edge function including its code',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      slug: functionSchema.shape.slug.describe('The slug identifier of the function'),
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    withUsageTracking('get-function', async (args: any) => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/functions/${encodeURIComponent(args.slug)}`, {
          method: 'GET',
          headers: { 'x-api-key': getApiKey(args.apiKey) },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' details`, result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error getting function: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  if (isRemote) {
    // Remote mode: accept inline code string directly
    registerTool(
      'update-function',
      'Update an existing edge function code or metadata',
      {
        apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
        slug: functionSchema.shape.slug.describe('The slug identifier of the function to update'),
        ...updateFunctionRequestSchema.omit({ code: true }).shape,
        code: z.string().optional().describe(
          'The new function code as a string. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      withUsageTracking('update-function', async (args: any) => {
        try {
          const updateData: UpdateFunctionRequest = {};
          if (args.name) updateData.name = args.name;
          if (args.code) updateData.code = args.code;
          if (args.description !== undefined) updateData.description = args.description;
          if (args.status) updateData.status = args.status;

          const response = await fetch(`${API_BASE_URL}/api/functions/${encodeURIComponent(args.slug)}`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': getApiKey(args.apiKey),
            },
            body: JSON.stringify(updateData),
          });

          const result = await handleApiResponse(response);
          return await addBackgroundContext({
            content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' updated successfully`, result) }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error updating function: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  } else {
    // Local mode: read code from local file path
    registerTool(
      'update-function',
      'Update an existing edge function code or metadata',
      {
        apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
        slug: functionSchema.shape.slug.describe('The slug identifier of the function to update'),
        ...updateFunctionRequestSchema.omit({ code: true }).shape,
        codeFile: z.string().optional().describe(
          'Path to JavaScript file containing the new function code. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      withUsageTracking('update-function', async (args: any) => {
        try {
          const updateData: UpdateFunctionRequest = {};
          if (args.name) updateData.name = args.name;

          if (args.codeFile) {
            try {
              updateData.code = await fs.readFile(args.codeFile, 'utf-8');
            } catch (fileError) {
              throw new Error(
                `Failed to read code file '${args.codeFile}': ${fileError instanceof Error ? fileError.message : 'Unknown error'}`,
                { cause: fileError }
              );
            }
          }

          if (args.description !== undefined) updateData.description = args.description;
          if (args.status) updateData.status = args.status;

          const response = await fetch(`${API_BASE_URL}/api/functions/${encodeURIComponent(args.slug)}`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': getApiKey(args.apiKey),
            },
            body: JSON.stringify(updateData),
          });

          const result = await handleApiResponse(response);
          const fileInfo = args.codeFile ? ` from ${args.codeFile}` : '';

          return await addBackgroundContext({
            content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' updated successfully${fileInfo}`, result) }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error updating function: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  }

  registerTool(
    'delete-function',
    'Delete an edge function permanently',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      slug: functionSchema.shape.slug.describe('The slug identifier of the function to delete'),
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    withUsageTracking('delete-function', async (args: any) => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/functions/${encodeURIComponent(args.slug)}`, {
          method: 'DELETE',
          headers: { 'x-api-key': getApiKey(args.apiKey) },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage(`Edge function '${args.slug}' deleted successfully`, result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error deleting function: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );
}
