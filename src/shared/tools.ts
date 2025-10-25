import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { handleApiResponse, formatSuccessMessage } from './response-handler.js';
import { UsageTracker } from './usage-tracker.js';
import {
  CreateBucketRequest,
  createBucketRequestSchema,
  rawSQLRequestSchema,
  RawSQLRequest,
  FunctionUpdateRequest,
  functionUpdateRequestSchema,
  functionUploadRequestSchema,
  bulkUpsertRequestSchema,
} from '@insforge/shared-schemas';
import FormData from 'form-data';

/**
 * Configuration for the tools
 */
export interface ToolsConfig {
  apiKey?: string;
  apiBaseUrl?: string;
}

/**
 * Register all Insforge tools on an MCP server
 * This centralizes all tool definitions to avoid duplication
 */
export function registerInsforgeTools(server: McpServer, config: ToolsConfig = {}) {
  const GLOBAL_API_KEY = config.apiKey || process.env.API_KEY || '';
  const API_BASE_URL = config.apiBaseUrl || process.env.API_BASE_URL || 'http://localhost:7130';

  // Initialize usage tracker
  const usageTracker = new UsageTracker(API_BASE_URL, GLOBAL_API_KEY);

  // Helper function to track tool usage
  async function trackToolUsage(toolName: string, success: boolean = true): Promise<void> {
    if (GLOBAL_API_KEY) {
      await usageTracker.trackUsage(toolName, success);
    }
  }

  // Wrapper function to add usage tracking to tools
  function withUsageTracking<T extends unknown[], R>(
    toolName: string,
    handler: (...args: T) => Promise<R>
  ): (...args: T) => Promise<R> {
    return async (...args: T): Promise<R> => {
      try {
        const result = await handler(...args);
        await trackToolUsage(toolName, true);
        return result;
      } catch (error) {
        await trackToolUsage(toolName, false);
        throw error;
      }
    };
  }

  // Helper function to get API key - always uses global API key
  // The optional parameter is kept for backward compatibility but ignored
  const getApiKey = (_toolApiKey?: string): string => {
    if (!GLOBAL_API_KEY) {
      throw new Error('API key is required. Pass --api_key when starting the MCP server.');
    }
    return GLOBAL_API_KEY;
  };

  // Helper function to fetch documentation from backend
  const fetchDocumentation = async (docType: string): Promise<string> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/docs/${docType}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const result = await handleApiResponse(response);

      if (result && typeof result === 'object' && 'content' in result) {
        let content = result.content;
        content = content.replace(/http:\/\/localhost:7130/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${docType} documentation: ${errMsg}`);
    }
  };

  // Helper function to fetch insforge-project.md content
  // const fetchInsforgeInstructionsContext = async (): Promise<string | null> => {
  //   try {
  //     return await fetchDocumentation('instructions');
  //   } catch (error) {
  //     console.error('Failed to fetch insforge-instructions.md:', error);
  //     return null;
  //   }
  // };

  // Helper function to add background context to responses
  // DISABLED: No longer appending background context to every response
  // const addBackgroundContext = async (response: any): Promise<any> => {
  //   const context = await fetchInsforgeInstructionsContext();
  //   if (context && response.content && Array.isArray(response.content)) {
  //     response.content.push({
  //       type: 'text',
  //       text: `\n\n---\n🔧 INSFORGE DEVELOPMENT RULES (Auto-loaded):\n${context}`,
  //     });
  //   }
  //   return response;
  // };

  // --------------------------------------------------
  // INSTRUCTION TOOLS
  // --------------------------------------------------

  server.tool(
    'get-docs',
    'Fetch Insforge documentation. Use "instructions" for essential backend setup (MANDATORY FIRST), or select specific SDK docs for database, auth, storage, functions, or AI integration.',
    {
      docType: z
        .enum(['instructions', 'db-sdk', 'auth-sdk', 'storage-sdk', 'functions-sdk', 'ai-integration-sdk'])
        .describe(
          'Documentation type: "instructions" (essential backend setup - use FIRST), "db-sdk" (database operations), "auth-sdk" (authentication), "storage-sdk" (file storage), "functions-sdk" (edge functions), "ai-integration-sdk" (AI features)'
        ),
    },
    withUsageTracking('get-docs', async ({ docType }) => {
      try {
        const content = await fetchDocumentation(docType);
        return {
          content: [
            {
              type: 'text',
              text: content,
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error fetching ${docType} documentation: ${errMsg}` }],
        };
      }
    })
  );

  // DISABLED: API key is set globally via --api_key flag, no need to expose it as a tool
  // server.tool(
  //   'get-api-key',
  //   'Retrieves the API key for the Insforge OSS backend. This is used to authenticate all requests to the backend.',
  //   {},
  //   async () => {
  //     try {
  //       return {
  //         content: [{ type: 'text', text: `API key: ${getApiKey()}` }],
  //       };
  //     } catch (error) {
  //       const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
  //       return {
  //         content: [{ type: 'text', text: `Error: ${errMsg}` }],
  //       };
  //     }
  //   }
  // );

  server.tool(
    'get-anon-key',
    'Generate an anonymous JWT token that never expires. Requires admin API key. Use this for client-side applications that need public access.',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
    },
    withUsageTracking('get-anon-key', async ({ apiKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/auth/tokens/anon`, {
          method: 'POST',
          headers: {
            'x-api-key': actualApiKey,
            'Content-Type': 'application/json',
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Anonymous token generated', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error generating anonymous token: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  // --------------------------------------------------
  // DATABASE TOOLS
  // --------------------------------------------------

  server.tool(
    'get-table-schema',
    'Returns the detailed schema(including RLS, indexes, constraints, etc.) of a specific table',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      tableName: z.string().describe('Name of the table'),
    },
    withUsageTracking('get-table-schema', async ({ apiKey, tableName }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/metadata/${tableName}`, {
          method: 'GET',
          headers: {
            'x-api-key': actualApiKey,
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Schema retrieved', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error getting table schema: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'get-backend-metadata',
    'Index all backend metadata',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
    },
    withUsageTracking('get-backend-metadata', async ({ apiKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/metadata?mcp=true`, {
          method: 'GET',
          headers: {
            'x-api-key': actualApiKey,
          },
        });

        const metadata = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: `Backend metadata:\n\n${JSON.stringify(metadata, null, 2)}`,
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error retrieving backend metadata: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'run-raw-sql',
    'Execute raw SQL query with optional parameters. Admin access required. Use with caution as it can modify data directly.',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      ...rawSQLRequestSchema.shape,
    },
    withUsageTracking('run-raw-sql', async ({ apiKey, query, params }) => {
      try {
        const actualApiKey = getApiKey(apiKey);

        const requestBody: RawSQLRequest = {
          query,
          params: params || [],
        };

        const response = await fetch(`${API_BASE_URL}/api/database/advance/rawsql`, {
          method: 'POST',
          headers: {
            'x-api-key': actualApiKey,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('SQL query executed', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error executing SQL query: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'bulk-upsert',
    'Bulk insert or update data from CSV or JSON file. Supports upsert operations with a unique key.',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      ...bulkUpsertRequestSchema.shape,
      filePath: z.string().describe('Path to CSV or JSON file containing data to import'),
    },
    withUsageTracking('bulk-upsert', async ({ apiKey, table, filePath, upsertKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        
        // Read the file
        const fileBuffer = await fs.readFile(filePath);
        const fileName = filePath.split('/').pop() || 'data.csv';
        
        // Create form data for multipart upload
        const formData = new FormData();
        formData.append('file', fileBuffer, fileName);
        formData.append('table', table);
        if (upsertKey) {
          formData.append('upsertKey', upsertKey);
        }
        
        const response = await fetch(`${API_BASE_URL}/api/database/advance/bulk-upsert`, {
          method: 'POST',
          headers: {
            'x-api-key': actualApiKey,
            ...formData.getHeaders(),
          },
          body: formData,
        });
        
        const result = await handleApiResponse(response);
        
        // Format the result message
        const message = result.success
          ? `Successfully processed ${result.rowsAffected} of ${result.totalRecords} records into table "${result.table}"`
          : result.message || 'Bulk upsert operation completed';

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Bulk upsert completed', {
                message,
                table: result.table,
                rowsAffected: result.rowsAffected,
                totalRecords: result.totalRecords,
                errors: result.errors,
              }),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error performing bulk upsert: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  // --------------------------------------------------
  // STORAGE TOOLS
  // --------------------------------------------------

  server.tool(
    'create-bucket',
    'Create new storage bucket',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      ...createBucketRequestSchema.shape,
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

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Bucket created', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error creating bucket: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'list-buckets',
    'Lists all storage buckets',
    {},
    withUsageTracking('list-buckets', async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/storage/buckets`, {
          method: 'GET',
          headers: {
            'x-api-key': getApiKey(),
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Buckets retrieved', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error listing buckets: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'delete-bucket',
    'Deletes a storage bucket',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      bucketName: z.string().describe('Name of the bucket to delete'),
    },
    withUsageTracking('delete-bucket', async ({ apiKey, bucketName }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/storage/buckets/${bucketName}`, {
          method: 'DELETE',
          headers: {
            'x-api-key': actualApiKey,
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Bucket deleted', result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error deleting bucket: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  // --------------------------------------------------
  // EDGE FUNCTION TOOLS
  // --------------------------------------------------

  server.tool(
    'create-function',
    'Create a new edge function that runs in Deno runtime. The code must be written to a file first for version control',
    {
      ...functionUploadRequestSchema.omit({ code: true }).shape,
      codeFile: z
        .string()
        .describe(
          'Path to JavaScript file containing the function code. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
    },
    withUsageTracking('create-function', async (args) => {
      try {
        let code: string;
        try {
          code = await fs.readFile(args.codeFile, 'utf-8');
        } catch (fileError) {
          throw new Error(
            `Failed to read code file '${args.codeFile}': ${fileError instanceof Error ? fileError.message : 'Unknown error'}`
          );
        }

        const response = await fetch(`${API_BASE_URL}/api/functions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': getApiKey(),
          },
          body: JSON.stringify({
            slug: args.slug,
            name: args.name,
            code: code,
            description: args.description,
            status: args.status,
          }),
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(
                `Edge function '${args.slug}' created successfully from ${args.codeFile}`,
                result
              ),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error creating function: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'get-function',
    'Get details of a specific edge function including its code',
    {
      slug: z.string().describe('The slug identifier of the function'),
    },
    withUsageTracking('get-function', async (args) => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/functions/${args.slug}`, {
          method: 'GET',
          headers: {
            'x-api-key': getApiKey(),
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Edge function '${args.slug}' details`, result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error getting function: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'update-function',
    'Update an existing edge function code or metadata',
    {
      slug: z.string().describe('The slug identifier of the function to update'),
      ...functionUpdateRequestSchema.omit({ code: true }).shape,
      codeFile: z
        .string()
        .optional()
        .describe(
          'Path to JavaScript file containing the new function code. Must export: module.exports = async function(request) { return new Response(...) }'
        ),
    },
    withUsageTracking('update-function', async (args) => {
      try {
        const updateData: FunctionUpdateRequest = {};
        if (args.name) {
          updateData.name = args.name;
        }

        if (args.codeFile) {
          try {
            updateData.code = await fs.readFile(args.codeFile, 'utf-8');
          } catch (fileError) {
            throw new Error(
              `Failed to read code file '${args.codeFile}': ${fileError instanceof Error ? fileError.message : 'Unknown error'}`
            );
          }
        }

        if (args.description !== undefined) {
          updateData.description = args.description;
        }
        if (args.status) {
          updateData.status = args.status;
        }

        const response = await fetch(`${API_BASE_URL}/api/functions/${args.slug}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': getApiKey(),
          },
          body: JSON.stringify(updateData),
        });

        const result = await handleApiResponse(response);

        const fileInfo = args.codeFile ? ` from ${args.codeFile}` : '';

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(
                `Edge function '${args.slug}' updated successfully${fileInfo}`,
                result
              ),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error updating function: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  server.tool(
    'delete-function',
    'Delete an edge function permanently',
    {
      slug: z.string().describe('The slug identifier of the function to delete'),
    },
    withUsageTracking('delete-function', async (args) => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/functions/${args.slug}`, {
          method: 'DELETE',
          headers: {
            'x-api-key': getApiKey(),
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Edge function '${args.slug}' deleted successfully`, result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error deleting function: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  // --------------------------------------------------
  // CONTAINER LOGS TOOLS
  // --------------------------------------------------

  server.tool(
    'get-container-logs',
    'Get latest logs from a specific container/service. Use this to help debug problems with your app.',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      source: z.enum(['insforge.logs', 'postgREST.logs', 'postgres.logs', 'function.logs']).describe('Log source to retrieve'),
      limit: z.number().optional().default(20).describe('Number of logs to return (default: 20)'),
    },
    withUsageTracking('get-container-logs', async ({ apiKey, source, limit }) => {
      try {
        const actualApiKey = getApiKey(apiKey);

        const queryParams = new URLSearchParams();
        if (limit) queryParams.append('limit', limit.toString());

        const response = await fetch(`${API_BASE_URL}/api/logs/analytics/${source}?${queryParams}`, {
          method: 'GET',
          headers: {
            'x-api-key': actualApiKey,
          },
        });

        const result = await handleApiResponse(response);

        return {
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Latest logs from ${source}`, result),
            },
          ],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error retrieving container logs: ${errMsg}`,
            },
          ],
          isError: true,
        };
      }
    })
  );

  // Return the configured values for reference
  return {
    apiKey: GLOBAL_API_KEY,
    apiBaseUrl: API_BASE_URL,
    toolCount: 14,
  };
}