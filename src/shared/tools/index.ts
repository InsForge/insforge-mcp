import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import fetch from 'node-fetch';
import { handleApiResponse } from '../response-handler.js';
import { UsageTracker } from '../usage-tracker.js';
import { registerDocsTools } from './docs.js';
import { registerDatabaseTools } from './database.js';
import { registerStorageTools } from './storage.js';
import { registerFunctionTools } from './functions.js';
import { registerDeploymentTools } from './deployment.js';
import type { RegisterContext } from './types.js';

/**
 * Configuration for the tools
 */
export interface ToolsConfig {
  apiKey?: string;
  apiBaseUrl?: string;
  mode?: 'local' | 'remote';
  projectId?: string;
  accessToken?: string;
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
  'bulk-upsert', // Requires reading local data file (filePath is required)
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
 */
function shouldRegisterTool(toolName: string, backendVersion: string): boolean {
  const requirement = TOOL_VERSION_REQUIREMENTS[toolName];

  if (!requirement) return true;

  const { minVersion, maxVersion } = requirement;

  if (minVersion && compareVersions(backendVersion, minVersion) < 0) return false;
  if (maxVersion && compareVersions(backendVersion, maxVersion) > 0) return false;

  return true;
}

/**
 * Fetch backend version from health endpoint
 * @throws Error if backend is unreachable
 */
async function fetchBackendVersion(apiBaseUrl: string): Promise<string> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(`${apiBaseUrl}/api/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Health check failed with status ${response.status}`);
    }

    const health = await response.json() as HealthCheckResponse;
    if (!health.version || typeof health.version !== 'string') {
      throw new Error('Health check returned invalid version field');
    }
    return health.version;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`Health check timed out after 10s — is the backend running at ${apiBaseUrl}?`, { cause: error });
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Register all Insforge tools on an MCP server.
 * Tools are split by domain into separate modules; this function
 * sets up the shared context and delegates to each domain registrar.
 */
export async function registerInsforgeTools(server: McpServer, config: ToolsConfig = {}) {
  const GLOBAL_API_KEY = config.apiKey || process.env.API_KEY || '';
  const API_BASE_URL = config.apiBaseUrl || process.env.API_BASE_URL || 'http://localhost:7130';
  const isRemote = config.mode === 'remote';

  const usageTracker = new UsageTracker(API_BASE_URL, GLOBAL_API_KEY, {
    projectId: config.projectId,
    accessToken: config.accessToken,
    isRemote,
  });

  let backendVersion: string;
  try {
    backendVersion = await fetchBackendVersion(API_BASE_URL);
    console.error(`Backend version: ${backendVersion}`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to fetch backend version: ${msg}`);
    throw new Error(`Cannot initialize tools: backend at ${API_BASE_URL} is unreachable. ${msg}`, { cause: error });
  }

  let toolCount = 0;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (toolName: string, ...args: any[]): boolean => {
    if (isRemote && LOCAL_ONLY_TOOLS.has(toolName)) {
      console.error(`Skipping tool '${toolName}': requires local filesystem (remote mode)`);
      return false;
    }
    if (shouldRegisterTool(toolName, backendVersion)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

  async function trackToolUsage(toolName: string, success = true): Promise<void> {
    if (GLOBAL_API_KEY) {
      await usageTracker.trackUsage(toolName, success).catch((err: unknown) => {
        console.error(`Failed to track usage for '${toolName}':`, err);
      });
    }
  }

  function withUsageTracking<T extends unknown[], R>(
    toolName: string,
    handler: (...args: T) => Promise<R>
  ): (...args: T) => Promise<R> {
    return async (...args: T): Promise<R> => {
      try {
        const result = await handler(...args);
        // Treat structured error responses (isError: true) as failures
        const isStructuredError =
          result !== null &&
          typeof result === 'object' &&
          'isError' in (result as Record<string, unknown>) &&
          (result as Record<string, unknown>)['isError'] === true;
        // Fire-and-forget: trackToolUsage already handles errors internally
        void trackToolUsage(toolName, !isStructuredError);
        return result;
      } catch (error) {
        void trackToolUsage(toolName, false);
        throw error;
      }
    };
  }

  const getApiKey = (toolApiKey?: string): string => {
    const apiKey = toolApiKey?.trim() || GLOBAL_API_KEY;
    if (!apiKey) {
      throw new Error('API key is required. Pass --api_key when starting the MCP server.');
    }
    return apiKey;
  };

  const addBackgroundContext = async <T extends { content: Array<{ type: 'text'; text: string }> }>(
    response: T
  ): Promise<T> => {
    const isLegacyVersion = compareVersions(backendVersion, '1.1.7') < 0;

    if (isLegacyVersion) {
      try {
        const docResponse = await fetch(`${API_BASE_URL}/api/docs/instructions`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });

        if (docResponse.ok) {
          const result = await handleApiResponse(docResponse);
          if (result && typeof result === 'object' && 'content' in result) {
            response.content.push({
              type: 'text' as const,
              text: `\n\n---\n🔧 INSFORGE DEVELOPMENT RULES (Auto-loaded):\n${result.content}`,
            });
          }
        }
      } catch (error) {
        console.error('Failed to fetch insforge-instructions.md:', error);
      }
    }

    return response;
  };

  const ctx: RegisterContext = {
    API_BASE_URL,
    isRemote,
    registerTool,
    withUsageTracking,
    getApiKey,
    addBackgroundContext,
  };

  // Register all domain tools
  registerDocsTools(ctx);
  registerDatabaseTools(ctx);
  registerStorageTools(ctx);
  registerFunctionTools(ctx);
  registerDeploymentTools(ctx);

  return {
    apiKey: GLOBAL_API_KEY,
    apiBaseUrl: API_BASE_URL,
    backendVersion,
    toolCount,
  };
}
