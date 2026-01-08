import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
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
  docTypeSchema,
} from '@insforge/shared-schemas';
import FormData from 'form-data';

const execAsync = promisify(exec);

/**
 * Configuration for the tools
 */
export interface ToolsConfig {
  apiKey?: string;
  apiBaseUrl?: string;
}

/**
 * Health check response from backend
 */
interface HealthCheckResponse {
  status: string;
  version: string;
  service: string;
  timestamp: string;
}

/**
 * Version cache entry
 */
interface VersionCacheEntry {
  version: string;
  timestamp: number;
}

/**
 * Tool version requirements map
 * Maps tool names to their minimum required backend version
 */
const TOOL_VERSION_REQUIREMENTS: Record<string, string> = {
  'upsert-schedule': '1.1.1',
  // 'get-schedules': '1.1.1',
  // 'get-schedule-logs': '1.1.1',
  'delete-schedule': '1.1.1',
};

/**
 * Register all Insforge tools on an MCP server
 * This centralizes all tool definitions to avoid duplication
 */
export function registerInsforgeTools(server: McpServer, config: ToolsConfig = {}) {
  const GLOBAL_API_KEY = config.apiKey || process.env.API_KEY || '';
  const API_BASE_URL = config.apiBaseUrl || process.env.API_BASE_URL || 'http://localhost:7130';

  // Initialize usage tracker
  const usageTracker = new UsageTracker(API_BASE_URL, GLOBAL_API_KEY);

  // Version cache with 5-minute TTL
  let versionCache: VersionCacheEntry | null = null;
  const VERSION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds

  /**
   * Fetch backend version from health endpoint with caching
   */
  async function getBackendVersion(): Promise<string> {
    const now = Date.now();

    // Return cached version if still valid
    if (versionCache && (now - versionCache.timestamp) < VERSION_CACHE_TTL) {
      return versionCache.version;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Health check failed with status ${response.status}`);
      }

      const health: HealthCheckResponse = await response.json();

      // Cache the version
      versionCache = {
        version: health.version,
        timestamp: now,
      };

      return health.version;
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to fetch backend version: ${errMsg}`);
    }
  }

  /**
   * Compare semantic versions (e.g., "1.1.0" vs "1.0.0")
   * Returns: -1 if v1 < v2, 0 if v1 === v2, 1 if v1 > v2
   */
  function compareVersions(v1: string, v2: string): number {
    // Strip 'v' prefix if present and remove pre-release metadata (e.g., "-dev.31")
    const clean1 = v1.replace(/^v/, '').split('-')[0];
    const clean2 = v2.replace(/^v/, '').split('-')[0];

    const parts1 = clean1.split('.').map(Number);
    const parts2 = clean2.split('.').map(Number);

    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const part1 = parts1[i] || 0;
      const part2 = parts2[i] || 0;

      if (part1 > part2) return 1;
      if (part1 < part2) return -1;
    }

    return 0;
  }

  /**
   * Check if tool is supported by current backend version
   * @throws Error if version requirement is not met
   */
  async function checkToolVersion(toolName: string): Promise<void> {
    const requiredVersion = TOOL_VERSION_REQUIREMENTS[toolName];

    // If no version requirement, tool is available in all versions
    if (!requiredVersion) {
      return;
    }

    try {
      const currentVersion = await getBackendVersion();

      if (compareVersions(currentVersion, requiredVersion) < 0) {
        throw new Error(
          `Tool '${toolName}' requires backend version ${requiredVersion} or higher, but current version is ${currentVersion}. Please upgrade your Insforge backend server.`
        );
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('requires backend version')) {
        throw error; // Re-throw version mismatch errors
      }
      // If health check fails, log warning but allow tool to proceed
      console.warn(`Warning: Could not verify backend version for tool '${toolName}': ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

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

      // Check for 404 before processing response
      if (response.status === 404) {
        throw new Error('Documentation not found. This feature may not be supported in your project version. Please contact the Insforge team for assistance.');
      }

      const result = await handleApiResponse(response);

      if (result && typeof result === 'object' && 'content' in result) {
        let content = result.content;
        // Replace all example/placeholder URLs with actual API_BASE_URL
        // Handle URLs whether they're in backticks, quotes, or standalone
        // Preserve paths after the domain by only replacing the base URL
        content = content.replace(/http:\/\/localhost:7130/g, API_BASE_URL);
        content = content.replace(/https:\/\/your-app\.region\.insforge\.app/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${docType} documentation: ${errMsg}`);
    }
  };

  // Helper function to fetch insforge-project.md content
  const fetchInsforgeInstructionsContext = async (): Promise<string | null> => {
    try {
      return await fetchDocumentation('instructions');
    } catch (error) {
      console.error('Failed to fetch insforge-instructions.md:', error);
      return null;
    }
  };

  // Helper function to add background context to responses
  // Only enabled for backend versions < 1.1.7 (legacy support)
  const addBackgroundContext = async <T extends { content: Array<{ type: 'text'; text: string }> }>(response: T): Promise<T> => {
    try {
      const currentVersion = await getBackendVersion();
      const isLegacyVersion = compareVersions(currentVersion, '1.1.7') < 0;

      // Only add context for versions before 1.1.7
      if (isLegacyVersion) {
        const context = await fetchInsforgeInstructionsContext();
        if (context && response.content && Array.isArray(response.content)) {
          response.content.push({
            type: 'text' as const,
            text: `\n\n---\n🔧 INSFORGE DEVELOPMENT RULES (Auto-loaded):\n${context}`,
          });
        }
      }
    } catch {
      // If version check fails, skip background context (safer default)
      console.warn('Could not determine backend version, skipping background context');
    }
    return response;
  };

  
  // --------------------------------------------------
  // INSTRUCTION TOOLS
  // --------------------------------------------------

  server.tool(
    'fetch-docs',
    'Fetch Insforge documentation. Use "instructions" for essential backend setup (MANDATORY FIRST), or select specific SDK docs for database, auth, storage, functions, or AI integration.',
    {
      docType: docTypeSchema
    },
    withUsageTracking('fetch-docs', async ({ docType }) => {
      try {
        const content = await fetchDocumentation(docType);

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: content,
            },
          ],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';

        // Friendly error for not found (likely due to old backend version)
        if (errMsg.includes('404') || errMsg.toLowerCase().includes('not found')) {
          return {
            content: [{
              type: 'text' as const,
              text: `Documentation for "${docType}" is not available. This is likely because your backend version is too old and doesn't support this documentation endpoint yet. This won't affect the functionality of the tools - they will still work correctly.`
            }],
          };
        }

        // Generic error response - no background context
        return {
          content: [{ type: 'text' as const, text: `Error fetching ${docType} documentation: ${errMsg}` }],
        };
      }
    })
  );

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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Anonymous token generated', result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Schema retrieved', result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: `Backend metadata:\n\n${JSON.stringify(metadata, null, 2)}`,
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('SQL query executed', result),
            },
          ],
        });
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

  /*
  server.tool(
    'download-template',
    'CRITICAL: MANDATORY FIRST STEP for all new InsForge projects. Download pre-configured starter template to a temporary directory. After download, you MUST copy files to current directory using the provided command.',
    {
      frame: z
        .enum(['react', 'nextjs'])
        .describe('Framework to use for the template (support React and Next.js)'),
      projectName: z
        .string()
        .optional()
        .describe('Name for the project directory (optional, defaults to "insforge-react")'),
    },
    withUsageTracking('download-template', async ({ frame, projectName }) => {
      try {
        // Get the anon key from backend
        const response = await fetch(`${API_BASE_URL}/api/auth/tokens/anon`, {
          method: 'POST',
          headers: {
            'x-api-key': getApiKey(),
            'Content-Type': 'application/json',
          },
        });

        const result = await handleApiResponse(response);
        const anonKey = result.accessToken;

        if (!anonKey) {
          throw new Error('Failed to retrieve anon key from backend');
        }

        // Create temp directory for download
        const tempDir = tmpdir();
        const targetDir = projectName || `insforge-${frame}`;
        const templatePath = `${tempDir}/${targetDir}`;

        console.error(`[download-template] Target path: ${templatePath}`);

        // Check if template already exists in temp, remove it first
        try {
          const stats = await fs.stat(templatePath);
          if (stats.isDirectory()) {
            console.error(`[download-template] Removing existing template at ${templatePath}`);
            await fs.rm(templatePath, { recursive: true, force: true });
          }
        } catch {
          // Directory doesn't exist, which is fine
        }

        const command = `npx create-insforge-app ${targetDir} --frame ${frame} --base-url ${API_BASE_URL} --anon-key ${anonKey} --skip-install`;

        // Execute the npx command in temp directory
        const { stdout, stderr } = await execAsync(command, {
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          cwd: tempDir,
        });

        // Check if command was successful (basic validation)
        const output = stdout || stderr || '';
        if (output.toLowerCase().includes('error') && !output.includes('successfully')) {
          throw new Error(`Failed to download template: ${output}`);
        }

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: `✅ React template downloaded successfully

📁 Template Location: ${templatePath}

⚠️  IMPORTANT: The template is in a temporary directory and NOT in your current working directory.

🔴 CRITICAL NEXT STEP REQUIRED:
You MUST copy ALL files (INCLUDING HIDDEN FILES like .env, .gitignore, etc.) from the temporary directory to your current project directory.

Copy all files from: ${templatePath}
To: Your current project directory
`,
            },
          ],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error downloading template: ${errMsg}`,
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

        return await addBackgroundContext({
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
        });
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
  */

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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Bucket created', result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Buckets retrieved', result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage('Bucket deleted', result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(
                `Edge function '${args.slug}' created successfully from ${args.codeFile}`,
                result
              ),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Edge function '${args.slug}' details`, result),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(
                `Edge function '${args.slug}' updated successfully${fileInfo}`,
                result
              ),
            },
          ],
        });
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

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Edge function '${args.slug}' deleted successfully`, result),
            },
          ],
        });
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

        let response = await fetch(`${API_BASE_URL}/api/logs/${source}?${queryParams}`, {
          method: 'GET',
          headers: {
            'x-api-key': actualApiKey,
          },
        });

        // Fallback to legacy endpoint if 404
        if (response.status === 404) {
          response = await fetch(`${API_BASE_URL}/api/logs/analytics/${source}?${queryParams}`, {
            method: 'GET',
            headers: {
              'x-api-key': actualApiKey,
            },
          });
        }

        const result = await handleApiResponse(response);

        return await addBackgroundContext({
          content: [
            {
              type: 'text',
              text: formatSuccessMessage(`Latest logs from ${source}`, result),
            },
          ],
        });
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

  // --------------------------------------------------
  // SCHEDULE TOOLS (CRON JOBS) - COMMENTED OUT
  // --------------------------------------------------

  // server.tool(
  //   'upsert-schedule',
  //   'Create or update a cron job schedule. If id is provided, updates existing schedule; otherwise creates a new one.',
  //   {
  //     apiKey: z
  //       .string()
  //       .optional()
  //       .describe('API key for authentication (optional if provided via --api_key)'),
  //     id: z
  //       .string()
  //       .uuid()
  //       .optional()
  //       .describe('The UUID of the schedule to update. If omitted, a new schedule will be created.'),
  //     name: z.string().min(3).describe('Schedule name (at least 3 characters)'),
  //     cronSchedule: z
  //       .string()
  //       .describe('Cron schedule format (5 or 6 parts, e.g., "0 */2 * * *" for every 2 hours)'),
  //     functionUrl: z.string().url().describe('The URL to call when the schedule triggers'),
  //     httpMethod: z
  //       .enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
  //       .optional()
  //       .default('POST')
  //       .describe('HTTP method to use'),
  //     headers: z
  //       .record(z.string())
  //       .optional()
  //       .describe('HTTP headers. Values starting with "secret:" will be resolved from secrets store.'),
  //     body: z
  //       .record(z.unknown())
  //       .optional()
  //       .describe('JSON body to send with the request'),
  //   },
  //   withUsageTracking('upsert-schedule', async ({ apiKey, id, name, cronSchedule, functionUrl, httpMethod, headers, body }) => {
  //     try {
  //       // Check backend version compatibility
  //       await checkToolVersion('upsert-schedule');

  //       const actualApiKey = getApiKey(apiKey);

  //       const requestBody: any = {
  //         name,
  //         cronSchedule,
  //         functionUrl,
  //         httpMethod: httpMethod || 'POST',
  //       };

  //       if (id) {
  //         requestBody.id = id;
  //       }
  //       if (headers) {
  //         requestBody.headers = headers;
  //       }
  //       if (body) {
  //         requestBody.body = body;
  //       }

  //       const response = await fetch(`${API_BASE_URL}/api/schedules`, {
  //         method: 'POST',
  //         headers: {
  //           'x-api-key': actualApiKey,
  //           'Content-Type': 'application/json',
  //         },
  //         body: JSON.stringify(requestBody),
  //       });

  //       const result = await handleApiResponse(response);

  //       const action = id ? 'updated' : 'created';
  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: formatSuccessMessage(`Schedule '${name}' ${action} successfully`, result),
  //           },
  //         ],
  //       });
  //     } catch (error) {
  //       const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
  //       return {
  //         content: [
  //           {
  //             type: 'text',
  //             text: `Error upserting schedule: ${errMsg}`,
  //           },
  //         ],
  //         isError: true,
  //       };
  //     }
  //   })
  // );

  // server.tool(
  //   'get-schedules',
  //   'List all cron job schedules',
  //   {
  //     apiKey: z
  //       .string()
  //       .optional()
  //       .describe('API key for authentication (optional if provided via --api_key)'),
  //     scheduleId: z
  //       .string()
  //       .uuid()
  //       .optional()
  //       .describe('Optional: Get a specific schedule by ID. If omitted, returns all schedules.'),
  //   },
  //   withUsageTracking('get-schedules', async ({ apiKey, scheduleId }) => {
  //     try {
  //       // Check backend version compatibility
  //       await checkToolVersion('get-schedules');

  //       const actualApiKey = getApiKey(apiKey);

  //       const url = scheduleId
  //         ? `${API_BASE_URL}/api/schedules/${scheduleId}`
  //         : `${API_BASE_URL}/api/schedules`;

  //       const response = await fetch(url, {
  //         method: 'GET',
  //         headers: {
  //           'x-api-key': actualApiKey,
  //         },
  //       });

  //       const result = await handleApiResponse(response);

  //       const message = scheduleId
  //         ? `Schedule details for ID: ${scheduleId}`
  //         : 'All schedules';

  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: formatSuccessMessage(message, result),
  //           },
  //         ],
  //       });
  //     } catch (error) {
  //       const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: `Error retrieving schedules: ${errMsg}`,
  //           },
  //         ],
  //         isError: true,
  //       });
  //     }
  //   })
  // );

  // server.tool(
  //   'get-schedule-logs',
  //   'Get execution logs for a specific schedule with pagination',
  //   {
  //     apiKey: z
  //       .string()
  //       .optional()
  //       .describe('API key for authentication (optional if provided via --api_key)'),
  //     scheduleId: z.string().uuid().describe('The UUID of the schedule to get logs for'),
  //     limit: z.number().int().positive().optional().default(50).describe('Number of logs to return (default: 50)'),
  //     offset: z.number().int().nonnegative().optional().default(0).describe('Number of logs to skip (default: 0)'),
  //   },
  //   withUsageTracking('get-schedule-logs', async ({ apiKey, scheduleId, limit, offset }) => {
  //     try {
  //       // Check backend version compatibility
  //       await checkToolVersion('get-schedule-logs');

  //       const actualApiKey = getApiKey(apiKey);

  //       const queryParams = new URLSearchParams();
  //       if (limit) queryParams.append('limit', limit.toString());
  //       if (offset) queryParams.append('offset', offset.toString());

  //       const response = await fetch(
  //         `${API_BASE_URL}/api/schedules/${scheduleId}/logs?${queryParams}`,
  //         {
  //           method: 'GET',
  //           headers: {
  //             'x-api-key': actualApiKey,
  //           },
  //         }
  //       );

  //       const result = await handleApiResponse(response);

  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: formatSuccessMessage(`Execution logs for schedule ${scheduleId}`, result),
  //           },
  //         ],
  //       });
  //     } catch (error) {
  //       const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: `Error retrieving schedule logs: ${errMsg}`,
  //           },
  //         ],
  //         isError: true,
  //       });
  //     }
  //   })
  // );

  // server.tool(
  //   'delete-schedule',
  //   'Delete a cron job schedule permanently',
  //   {
  //     apiKey: z
  //       .string()
  //       .optional()
  //       .describe('API key for authentication (optional if provided via --api_key)'),
  //     scheduleId: z.string().uuid().describe('The UUID of the schedule to delete'),
  //   },
  //   withUsageTracking('delete-schedule', async ({ apiKey, scheduleId }) => {
  //     try {
  //       // Check backend version compatibility
  //       await checkToolVersion('delete-schedule');

  //       const actualApiKey = getApiKey(apiKey);

  //       const response = await fetch(`${API_BASE_URL}/api/schedules/${scheduleId}`, {
  //         method: 'DELETE',
  //         headers: {
  //           'x-api-key': actualApiKey,
  //         },
  //       });

  //       const result = await handleApiResponse(response);

  //       return await addBackgroundContext({
  //         content: [
  //           {
  //             type: 'text',
  //             text: formatSuccessMessage(`Schedule ${scheduleId} deleted successfully`, result),
  //           },
  //         ],
  //       });
  //     } catch (error) {
  //       const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
  //       return {
  //         content: [
  //           {
  //             type: 'text',
  //             text: `Error deleting schedule: ${errMsg}`,
  //           },
  //         ],
  //         isError: true,
  //       };
  //     }
  //   })
  // );

  // Return the configured values for reference
  return {
    apiKey: GLOBAL_API_KEY,
    apiBaseUrl: API_BASE_URL,
    toolCount: 15,
  };
}