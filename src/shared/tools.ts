import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import archiver from 'archiver';
import { handleApiResponse, formatSuccessMessage } from './response-handler.js';
import { UsageTracker } from './usage-tracker.js';
import {
  CreateBucketRequest,
  createBucketRequestSchema,
  rawSQLRequestSchema,
  RawSQLRequest,
  UpdateFunctionRequest,
  updateFunctionRequestSchema,
  uploadFunctionRequestSchema,
  bulkUpsertRequestSchema,
  docTypeSchema,
  sdkFeatureSchema,
  sdkLanguageSchema,
  startDeploymentRequestSchema,
  StartDeploymentRequest,
  CreateDeploymentResponse,
} from '@insforge/shared-schemas';
import FormData from 'form-data';

const execAsync = promisify(exec);

/** Shell-escape a value by wrapping in single quotes and escaping embedded single quotes */
const shellEsc = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

/**
 * Configuration for the tools
 */
export interface ToolsConfig {
  apiKey?: string;
  apiBaseUrl?: string;
  mode?: 'local' | 'remote';
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
 * Tool version requirement specification
 * - minVersion: Minimum backend version required (inclusive)
 * - maxVersion: Maximum backend version supported (inclusive, for deprecated tools)
 * - Tools not in the map have no version requirements (available for all versions)
 */
interface ToolVersionRequirement {
  minVersion?: string;
  maxVersion?: string;
}

/**
 * Tool version requirements map
 * Maps tool names to their version requirements
 *
 * Examples:
 * - { minVersion: '1.1.0' } - Available from v1.1.0 onwards
 * - { maxVersion: '2.0.0' } - Deprecated after v2.0.0
 * - { minVersion: '1.1.0', maxVersion: '2.0.0' } - Available only between v1.1.0 and v2.0.0
 * - Not in map - Available for all versions
 */
const TOOL_VERSION_REQUIREMENTS: Record<string, ToolVersionRequirement> = {
  // Schedule tools - require backend v1.1.1+
  // 'upsert-schedule': { minVersion: '1.1.1' },
  // 'delete-schedule': { minVersion: '1.1.1' },
  // 'get-schedules': { minVersion: '1.1.1' },
  // 'get-schedule-logs': { minVersion: '1.1.1' },

  'create-deployment': { minVersion: '1.4.7' },
  'fetch-sdk-docs': { minVersion: '1.5.1' },

  // Example of a deprecated tool (uncomment when needed):
  // 'legacy-tool': { minVersion: '1.0.0', maxVersion: '1.5.0' },
};

/**
 * Tools that require local filesystem access and should only be
 * registered for stdio (local) transport, not HTTP (remote).
 */
const LOCAL_ONLY_TOOLS = new Set([
  'bulk-upsert',         // Requires reading local data file (filePath is required)
]);

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
 * Check if a tool should be registered based on backend version
 * @param toolName - Name of the tool to check
 * @param backendVersion - Current backend version
 * @returns true if tool should be registered, false otherwise
 */
function shouldRegisterTool(toolName: string, backendVersion: string): boolean {
  const requirement = TOOL_VERSION_REQUIREMENTS[toolName];

  // No requirement means tool is available for all versions
  if (!requirement) {
    return true;
  }

  const { minVersion, maxVersion } = requirement;

  // Check minimum version requirement
  if (minVersion && compareVersions(backendVersion, minVersion) < 0) {
    return false;
  }

  // Check maximum version requirement (for deprecated tools)
  if (maxVersion && compareVersions(backendVersion, maxVersion) > 0) {
    return false;
  }

  return true;
}

/**
 * Fetch backend version from health endpoint
 * @throws Error if backend is unreachable
 */
async function fetchBackendVersion(apiBaseUrl: string): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/api/health`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`);
  }

  const health = await response.json() as HealthCheckResponse;
  return health.version;
}

/**
 * Register all Insforge tools on an MCP server
 * This centralizes all tool definitions to avoid duplication
 * Tools are dynamically registered based on backend version compatibility
 */
export async function registerInsforgeTools(server: McpServer, config: ToolsConfig = {}) {
  const GLOBAL_API_KEY = config.apiKey || process.env.API_KEY || '';
  const API_BASE_URL = config.apiBaseUrl || process.env.API_BASE_URL || 'http://localhost:7130';
  const isRemote = config.mode === 'remote';

  // Initialize usage tracker
  const usageTracker = new UsageTracker(API_BASE_URL, GLOBAL_API_KEY);

  // Fetch backend version for dynamic tool registration (fails if backend is offline)
  const backendVersion = await fetchBackendVersion(API_BASE_URL);
  console.error(`Backend version: ${backendVersion}`);

  // Track registered tool count
  let toolCount = 0;

  // Helper to register a tool with version checking
  // Using 'any' for args to handle server.tool's multiple overloads
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (toolName: string, ...args: any[]) => {
    if (isRemote && LOCAL_ONLY_TOOLS.has(toolName)) {
      console.error(`Skipping tool '${toolName}': requires local filesystem (remote mode)`);
      return false;
    }
    if (shouldRegisterTool(toolName, backendVersion)) {
      (server.tool as any)(toolName, ...args);
      toolCount++;
      return true;
    } else {
      const req = TOOL_VERSION_REQUIREMENTS[toolName];
      const reason = req?.minVersion && compareVersions(backendVersion, req.minVersion) < 0
        ? `requires backend >= ${req.minVersion}`
        : `deprecated after backend ${req?.maxVersion}`;
      console.error(`Skipping tool '${toolName}': ${reason} (current: ${backendVersion})`);
      return false;
    }
  };

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
        content = content.replace(/https:\/\/your-app\.insforge\.app/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${docType} documentation: ${errMsg}`);
    }
  };

  const fetchSDKDocumentation = async (feature: string, language: string): Promise<string> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/docs/${feature}/${language}`, {
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
        content = content.replace(/https:\/\/your-app\.insforge\.app/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${feature}-${language} documentation: ${errMsg}`);
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
    const isLegacyVersion = compareVersions(backendVersion, '1.1.7') < 0;

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
    return response;
  };

  
  // --------------------------------------------------
  // INSTRUCTION TOOLS
  // --------------------------------------------------

  registerTool(
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

  registerTool(
    'fetch-sdk-docs',
    `Fetch Insforge SDK documentation for a specific feature and language combination.

Supported features: ${sdkFeatureSchema.options.join(', ')}
Supported languages: ${sdkLanguageSchema.options.join(', ')}`,
    {
      sdkFeature: sdkFeatureSchema,
      sdkLanguage: sdkLanguageSchema
    },
    withUsageTracking('fetch-sdk-docs', async ({ sdkFeature, sdkLanguage }) => {
      try {
        const content = await fetchSDKDocumentation(sdkFeature, sdkLanguage);

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
              text: `Documentation for "${sdkFeature}-${sdkLanguage}" is not available. This is likely because your backend version is too old and doesn't support this documentation endpoint yet. This won't affect the functionality of the tools - they will still work correctly.`
            }],
          };
        }

        // Generic error response - no background context
        return {
          content: [{ type: 'text' as const, text: `Error fetching ${sdkFeature}-${sdkLanguage} documentation: ${errMsg}` }],
        };
      }
    })
  );

  registerTool(
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

  registerTool(
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

  registerTool(
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

  registerTool(
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

  if (isRemote) {
    // Remote mode: fetch anon key and return npx command for agent to execute locally
    registerTool(
      'download-template',
      'CRITICAL: MANDATORY FIRST STEP for all new InsForge projects. Fetches configuration and returns a command for you to run locally to scaffold a starter template.',
      {
        frame: z
          .enum(['react', 'nextjs'])
          .describe('Framework to use for the template (support React and Next.js)'),
        projectName: z
          .string()
          .optional()
          .describe('Name for the project directory (optional, defaults to "insforge-{frame}")'),
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

          const targetDir = projectName || `insforge-${frame}`;

          const instructions = `Template configuration ready. Please run the following command in your project's parent directory:

\`\`\`bash
npx create-insforge-app ${shellEsc(targetDir)} --frame ${frame} --base-url ${shellEsc(API_BASE_URL)} --anon-key ${shellEsc(anonKey)}
\`\`\`

After the command completes, \`cd ${shellEsc(targetDir)}\` and start developing.`;

          return {
            content: [
              {
                type: 'text',
                text: instructions,
              },
            ],
          };
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [
              {
                type: 'text',
                text: `Error preparing template: ${errMsg}`,
              },
            ],
            isError: true,
          };
        }
      })
    );
  } else {
    // Local mode: execute npx command directly
    registerTool(
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
  }

  registerTool(
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

  // --------------------------------------------------
  // STORAGE TOOLS
  // --------------------------------------------------

  registerTool(
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

  registerTool(
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

  registerTool(
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

  if (isRemote) {
    // Remote mode: accept inline code string directly
    registerTool(
      'create-function',
      'Create a new edge function that runs in Deno runtime',
      {
        ...uploadFunctionRequestSchema.omit({ code: true }).shape,
        code: z
          .string()
          .describe(
            'The function code as a string. Must export: module.exports = async function(request) { return new Response(...) }'
          ),
      },
      withUsageTracking('create-function', async (args: any) => {
        try {
          const response = await fetch(`${API_BASE_URL}/api/functions`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': getApiKey(),
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
            content: [
              {
                type: 'text',
                text: formatSuccessMessage(
                  `Edge function '${args.slug}' created successfully`,
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
  } else {
    // Local mode: read code from local file path
    registerTool(
      'create-function',
      'Create a new edge function that runs in Deno runtime. The code must be written to a file first for version control',
      {
        ...uploadFunctionRequestSchema.omit({ code: true }).shape,
        codeFile: z
          .string()
          .describe(
            'Path to JavaScript file containing the function code. Must export: module.exports = async function(request) { return new Response(...) }'
          ),
      },
      withUsageTracking('create-function', async (args: any) => {
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
  }

  registerTool(
    'get-function',
    'Get details of a specific edge function including its code',
    {
      slug: z.string().describe('The slug identifier of the function'),
    },
    withUsageTracking('get-function', async (args: any) => {
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

  if (isRemote) {
    // Remote mode: accept inline code string directly
    registerTool(
      'update-function',
      'Update an existing edge function code or metadata',
      {
        slug: z.string().describe('The slug identifier of the function to update'),
        ...updateFunctionRequestSchema.omit({ code: true }).shape,
        code: z
          .string()
          .optional()
          .describe(
            'The new function code as a string. Must export: module.exports = async function(request) { return new Response(...) }'
          ),
      },
      withUsageTracking('update-function', async (args: any) => {
        try {
          const updateData: UpdateFunctionRequest = {};
          if (args.name) {
            updateData.name = args.name;
          }
          if (args.code) {
            updateData.code = args.code;
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

          return await addBackgroundContext({
            content: [
              {
                type: 'text',
                text: formatSuccessMessage(
                  `Edge function '${args.slug}' updated successfully`,
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
  } else {
    // Local mode: read code from local file path
    registerTool(
      'update-function',
      'Update an existing edge function code or metadata',
      {
        slug: z.string().describe('The slug identifier of the function to update'),
        ...updateFunctionRequestSchema.omit({ code: true }).shape,
        codeFile: z
          .string()
          .optional()
          .describe(
            'Path to JavaScript file containing the new function code. Must export: module.exports = async function(request) { return new Response(...) }'
          ),
      },
      withUsageTracking('update-function', async (args: any) => {
        try {
          const updateData: UpdateFunctionRequest = {};
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
  }

  registerTool(
    'delete-function',
    'Delete an edge function permanently',
    {
      slug: z.string().describe('The slug identifier of the function to delete'),
    },
    withUsageTracking('delete-function', async (args: any) => {
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

  registerTool(
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
  // DEPLOYMENT TOOLS
  // --------------------------------------------------

  if (isRemote) {
    // Remote mode: prepare deployment and return instructions for agent to execute locally
    registerTool(
      'create-deployment',
      'Prepare a deployment by creating a presigned upload URL. Returns shell commands for the agent to execute locally: zip the source directory and upload to cloud storage. After uploading, call the start-deployment tool to trigger the build.',
      {
        sourceDirectory: z.string().describe('Absolute path to the source directory containing files to deploy (e.g., /Users/name/project). Do not use relative paths like "."'),
      },
      withUsageTracking('create-deployment', async ({ sourceDirectory }) => {
        try {
          // Create deployment to get presigned upload URL
          const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
          });

          const createResult: CreateDeploymentResponse = await handleApiResponse(createResponse);
          const { id: deploymentId, uploadUrl, uploadFields } = createResult;

          const esc = shellEsc;

          // Build curl upload command with presigned fields
          const curlFields = Object.entries(uploadFields)
            .map(([key, value]) => `-F ${esc(`${key}=${value}`)}`)
            .join(' \\\n  ');

          const escapedDir = esc(sourceDirectory);
          const tmpZip = `/tmp/insforge-deploy-${deploymentId}.zip`;

          const instructions = `Deployment prepared successfully. Deployment ID: ${deploymentId}

Please execute the following commands locally, then call the \`start-deployment\` tool:

## Step 1: Zip the source directory
\`\`\`bash
cd ${escapedDir} && zip -r ${tmpZip} . \
  -x "node_modules/*" ".git/*" ".next/*" ".env" ".env.local" "dist/*" "build/*" ".DS_Store" "*.log"
\`\`\`

## Step 2: Upload the zip file
\`\`\`bash
curl -X POST ${esc(uploadUrl)} \
  ${curlFields} \
  -F 'file=@${tmpZip};type=application/zip'
\`\`\`

## Step 3: Clean up
\`\`\`bash
rm /tmp/insforge-deploy-${deploymentId}.zip
\`\`\`

## Step 4: Trigger the build
Call the \`start-deployment\` tool with deploymentId: "${deploymentId}"

Run each step in order. If any step fails, do not proceed to the next step.`;

          return {
            content: [
              {
                type: 'text',
                text: instructions,
              },
            ],
          };
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [
              {
                type: 'text',
                text: `Error preparing deployment: ${errMsg}`,
              },
            ],
            isError: true,
          };
        }
      })
    );

    // Remote mode: start-deployment tool triggers the build via API (keeps API key server-side)
    registerTool(
      'start-deployment',
      'Trigger a deployment build after uploading source code. Use this after executing the upload commands from create-deployment.',
      {
        deploymentId: z.string().describe('The deployment ID returned by create-deployment'),
        ...startDeploymentRequestSchema.shape,
      },
      withUsageTracking('start-deployment', async ({ deploymentId, projectSettings, envVars, meta }) => {
        try {
          const startBody: StartDeploymentRequest = {};
          if (projectSettings) startBody.projectSettings = projectSettings;
          if (envVars) startBody.envVars = envVars;
          if (meta) startBody.meta = meta;

          const startResponse = await fetch(`${API_BASE_URL}/api/deployments/${deploymentId}/start`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(startBody),
          });

          const startResult = await handleApiResponse(startResponse);

          return await addBackgroundContext({
            content: [
              {
                type: 'text',
                text: formatSuccessMessage('Deployment started', startResult) + '\n\nNote: You can check deployment status by querying the system.deployments table.',
              },
            ],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [
              {
                type: 'text',
                text: `Error starting deployment: ${errMsg}`,
              },
            ],
            isError: true,
          };
        }
      })
    );
  } else {
    // Local mode: zip, upload, and trigger deployment directly
    registerTool(
      'create-deployment',
      'Deploy source code from a directory. This tool zips files, uploads to cloud storage, and triggers deployment with optional environment variables and project settings.',
      {
        sourceDirectory: z.string().describe('Absolute path to the source directory containing files to deploy (e.g., /Users/name/project or C:\\Users\\name\\project). Do not use relative paths like "."'),
        ...startDeploymentRequestSchema.shape,
      },
      withUsageTracking('create-deployment', async ({ sourceDirectory, projectSettings, envVars, meta }) => {
        try {
          // Validate that sourceDirectory is an absolute path
          const isAbsolutePath = sourceDirectory.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(sourceDirectory);
          if (!isAbsolutePath) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Error: sourceDirectory must be an absolute path, not a relative path like "${sourceDirectory}". Please provide the full path to the source directory (e.g., /Users/name/project on macOS/Linux or C:\\Users\\name\\project on Windows).`,
                },
              ],
              isError: true,
            };
          }

          // Validate that sourceDirectory exists and is a directory
          try {
            const stats = await fs.stat(sourceDirectory);
            if (!stats.isDirectory()) {
              return {
                content: [
                  {
                    type: 'text' as const,
                    text: `Error: "${sourceDirectory}" is not a directory. Please provide a path to a directory containing the source code.`,
                  },
                ],
                isError: true,
              };
            }
          } catch (statError) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Error: Directory "${sourceDirectory}" does not exist or is not accessible. Please verify the path is correct.`,
                },
              ],
              isError: true,
            };
          }

          // Use the provided absolute path directly
          const resolvedSourceDir = sourceDirectory;

          // Step 1: Create deployment to get presigned upload URL
          const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
          });

          const createResult: CreateDeploymentResponse = await handleApiResponse(createResponse);
          const { id: deploymentId, uploadUrl, uploadFields } = createResult;

          // Step 2: Create zip in memory using archiver (cross-platform)
          // Use archive.directory() instead of glob() for better Windows compatibility
          const zipBuffer = await new Promise<Buffer>((resolve, reject) => {
            const archive = archiver('zip', { zlib: { level: 9 } });
            const chunks: Buffer[] = [];

            archive.on('data', (chunk: Buffer) => chunks.push(chunk));
            archive.on('end', () => resolve(Buffer.concat(chunks)));
            archive.on('error', (err: Error) => reject(err));

            // Patterns to exclude (normalized for cross-platform)
            const excludePatterns = [
              'node_modules',
              '.git',
              '.next',
              '.env',
              '.env.local',
              'dist',
              'build',
              '.DS_Store',
            ];

            // Add directory with filter function for cross-platform compatibility
            archive.directory(resolvedSourceDir, false, (entry) => {
              // Normalize path separators for cross-platform matching
              const normalizedName = entry.name.replace(/\\/g, '/');

              // Check if file should be excluded
              for (const pattern of excludePatterns) {
                if (normalizedName.startsWith(pattern + '/') ||
                    normalizedName === pattern ||
                    normalizedName.endsWith('/' + pattern) ||
                    normalizedName.includes('/' + pattern + '/')) {
                  return false;
                }
              }

              // Skip log files
              if (normalizedName.endsWith('.log')) {
                return false;
              }

              return entry; // Include this entry
            });

            archive.finalize();
          });

          // Step 3: Upload zip to presigned URL
          const uploadFormData = new FormData();

          // Add all presigned fields first
          for (const [key, value] of Object.entries(uploadFields)) {
            uploadFormData.append(key, value);
          }
          // Add the file last
          uploadFormData.append('file', zipBuffer, {
            filename: 'deployment.zip',
            contentType: 'application/zip',
          });

          const uploadResponse = await fetch(uploadUrl, {
            method: 'POST',
            body: uploadFormData,
            headers: uploadFormData.getHeaders(),
          });

          if (!uploadResponse.ok) {
            const uploadError = await uploadResponse.text();
            throw new Error(`Failed to upload zip file: ${uploadError}`);
          }

          // Step 4: Start the deployment
          const startBody: StartDeploymentRequest = {};
          if (projectSettings) startBody.projectSettings = projectSettings;
          if (envVars) startBody.envVars = envVars;
          if (meta) startBody.meta = meta;

          const startResponse = await fetch(`${API_BASE_URL}/api/deployments/${deploymentId}/start`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(startBody),
          });

          const startResult = await handleApiResponse(startResponse);

          return await addBackgroundContext({
            content: [
              {
                type: 'text',
                text: formatSuccessMessage('Deployment started', startResult) + '\n\nNote: You can check deployment status by querying the system.deployments table.',
              },
            ],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [
              {
                type: 'text',
                text: `Error creating deployment: ${errMsg}`,
              },
            ],
            isError: true,
          };
        }
      })
    );
  }

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
    toolCount,
    backendVersion,
  };
}
