import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import FormData from 'form-data';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import {
  RawSQLRequest,
  rawSQLRequestSchema,
  bulkUpsertRequestSchema,
} from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';

const execFileAsync = promisify(execFile);

/** Shell-escape a value by wrapping in single quotes and escaping embedded single quotes */
const shellEsc = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

export function registerDatabaseTools(ctx: RegisterContext): void {
  const { API_BASE_URL, isRemote, registerTool, withUsageTracking, getApiKey, addBackgroundContext } = ctx;

  // --------------------------------------------------
  // DATABASE TOOLS
  // --------------------------------------------------

  registerTool(
    'get-table-schema',
    'Returns the detailed schema(including RLS, indexes, constraints, etc.) of a specific table',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      tableName: z.string().describe('Name of the table'),
    },
    withUsageTracking('get-table-schema', async ({ apiKey, tableName }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/metadata/${tableName}`, {
          method: 'GET',
          headers: { 'x-api-key': actualApiKey },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage('Schema retrieved', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error getting table schema: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'get-backend-metadata',
    'Index all backend metadata',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
    },
    withUsageTracking('get-backend-metadata', async ({ apiKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/metadata?mcp=true`, {
          method: 'GET',
          headers: { 'x-api-key': actualApiKey },
        });

        const metadata = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: `Backend metadata:\n\n${JSON.stringify(metadata, null, 2)}` }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error retrieving backend metadata: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'run-raw-sql',
    'Execute raw SQL query with optional parameters. Admin access required. Use with caution as it can modify data directly.',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      ...rawSQLRequestSchema.shape,
    },
    withUsageTracking('run-raw-sql', async ({ apiKey, query, params }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const requestBody: RawSQLRequest = { query, params: params || [] };

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
          content: [{ type: 'text', text: formatSuccessMessage('SQL query executed', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error executing SQL query: ${errMsg}` }],
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
        frame: z.enum(['react', 'nextjs']).describe('Framework to use for the template (support React and Next.js)'),
        projectName: z.string().optional().describe('Name for the project directory (optional, defaults to "insforge-{frame}")'),
      },
      withUsageTracking('download-template', async ({ frame, projectName }) => {
        try {
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
            content: [{ type: 'text', text: instructions }],
          };
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error preparing template: ${errMsg}` }],
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
        frame: z.enum(['react', 'nextjs']).describe('Framework to use for the template (support React and Next.js)'),
        projectName: z.string().optional().describe('Name for the project directory (optional, defaults to "insforge-{frame}")'),
      },
      withUsageTracking('download-template', async ({ frame, projectName }) => {
        try {
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

          const rawDir = projectName || `insforge-${frame}`;

          // Reject path traversal and shell-unsafe names
          if (!rawDir || rawDir === '.' || rawDir === '..' || /[/\\]/.test(rawDir) || !/^[\w.-]+$/.test(rawDir)) {
            throw new Error('projectName must be a single directory name using only letters, numbers, hyphens, underscores, and dots');
          }

          const targetDir = rawDir;

          // Create a unique workspace to avoid collisions across concurrent runs
          const workspaceBase = await fs.mkdtemp(join(tmpdir(), 'insforge-template-'));
          const templatePath = join(workspaceBase, targetDir);

          console.error(`[download-template] Target path: ${templatePath}`);

          // execFileAsync rejects on non-zero exit — no fragile stdout/stderr inspection needed
          await execFileAsync(
            'npx',
            ['create-insforge-app', targetDir, '--frame', frame, '--base-url', API_BASE_URL, '--anon-key', anonKey, '--skip-install'],
            { maxBuffer: 10 * 1024 * 1024, cwd: workspaceBase }
          );

          const frameName = frame === 'nextjs' ? 'Next.js' : 'React';

          return await addBackgroundContext({
            content: [{
              type: 'text',
              text: `✅ ${frameName} template downloaded successfully

📁 Template Location: ${templatePath}

⚠️  IMPORTANT: The template is in a temporary directory and NOT in your current working directory.

🔴 CRITICAL NEXT STEP REQUIRED:
You MUST copy ALL files (INCLUDING HIDDEN FILES like .env, .gitignore, etc.) from the temporary directory to your current project directory.

Copy all files from: ${templatePath}
To: Your current project directory
`,
            }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error downloading template: ${errMsg}` }],
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
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      ...bulkUpsertRequestSchema.shape,
      filePath: z.string().describe('Path to CSV or JSON file containing data to import'),
    },
    withUsageTracking('bulk-upsert', async ({ apiKey, table, filePath, upsertKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);

        const fileBuffer = await fs.readFile(filePath);
        const fileName = filePath.split('/').pop() || 'data.csv';

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

        const message = result.success
          ? `Successfully processed ${result.rowsAffected} of ${result.totalRecords} records into table "${result.table}"`
          : result.message || 'Bulk upsert operation completed';

        return await addBackgroundContext({
          content: [{
            type: 'text',
            text: formatSuccessMessage('Bulk upsert completed', {
              message,
              table: result.table,
              rowsAffected: result.rowsAffected,
              totalRecords: result.totalRecords,
              errors: result.errors,
            }),
          }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error performing bulk upsert: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );
}
