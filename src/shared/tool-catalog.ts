/**
 * Curated catalog of MCP tools exposed by the InsForge MCP server.
 *
 * This catalog backs the `/.well-known/mcp/server-card.json` discovery document
 * (the ora / agent-readiness card). It is intentionally a flat, static list so the
 * card can be served unauthenticated without standing up a session or backend
 * connection.
 *
 * IMPORTANT: This list MUST stay in sync with the tools registered in
 * `src/shared/tools/{database,storage,functions,deployment,docs}.ts`. The
 * descriptions below are copied verbatim from the corresponding
 * `registerTool('<name>', '<description>', ...)` calls. When a tool is added,
 * removed, or its description changes, update this catalog as well.
 */
export const TOOL_CATALOG: { name: string; description: string }[] = [
  // database.ts
  {
    name: 'bulk-upsert',
    description:
      'Bulk insert or update data from CSV or JSON file. Supports upsert operations with a unique key.',
  },
  {
    name: 'get-backend-metadata',
    description: 'Index all backend metadata',
  },
  {
    name: 'get-table-schema',
    description:
      'Returns the detailed schema(including RLS, indexes, constraints, etc.) of a specific table',
  },
  {
    name: 'run-raw-sql',
    description:
      'Execute raw SQL query with optional parameters. Admin access required. Use with caution as it can modify data directly.',
  },
  // storage.ts
  {
    name: 'create-bucket',
    description: 'Create new storage bucket',
  },
  {
    name: 'delete-bucket',
    description: 'Deletes a storage bucket',
  },
  {
    name: 'list-buckets',
    description: 'Lists all storage buckets',
  },
  // functions.ts
  {
    name: 'create-function',
    description: 'Create a new edge function that runs in Deno runtime',
  },
  {
    name: 'delete-function',
    description: 'Delete an edge function permanently',
  },
  {
    name: 'get-function',
    description: 'Get details of a specific edge function including its code',
  },
  {
    name: 'update-function',
    description: 'Update an existing edge function code or metadata',
  },
  // deployment.ts
  {
    name: 'create-deployment',
    description:
      'Prepare a deployment upload. Direct-capable backends return direct file upload commands. Older backends use the legacy zip upload flow. After uploading, call the start-deployment tool to trigger the build.',
  },
  {
    name: 'get-container-logs',
    description:
      'Get latest logs from a specific container/service. Use this to help debug problems with your app.',
  },
  {
    name: 'start-deployment',
    description:
      'Trigger a deployment build after uploading source code. Use this after executing the upload commands from create-deployment.',
  },
  // docs.ts
  {
    name: 'download-template',
    description:
      'CRITICAL: MANDATORY FIRST STEP for all new InsForge projects. Fetches configuration and returns a command for you to run locally to scaffold a starter template.',
  },
  {
    name: 'fetch-docs',
    description:
      'Fetch Insforge documentation. Use "instructions" for essential backend setup (MANDATORY FIRST), or select specific SDK docs for database, auth, storage, functions, or AI integration.',
  },
  {
    name: 'fetch-sdk-docs',
    description:
      'Fetch Insforge SDK documentation for a specific feature and language combination.',
  },
  {
    name: 'get-anon-key',
    description:
      'Generate an anonymous JWT token that never expires. Requires admin API key. Use this for client-side applications that need public access.',
  },
];
