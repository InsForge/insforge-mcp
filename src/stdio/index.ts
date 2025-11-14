import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { program } from 'commander';
import { registerInsforgeTools } from '../shared/tools.js';
import { setWorkspaceRoots } from '../shared/context.js';

// Parse command line arguments
program.option('--api_key <value>', 'API Key');
program.parse(process.argv);
const options = program.opts();
const { api_key } = options;

// Create MCP server
const server = new McpServer({
  name: 'insforge-mcp',
  version: '1.0.0',
});

// Register all Insforge tools with the server
const toolsConfig = registerInsforgeTools(server, {
  apiKey: api_key,
  apiBaseUrl: process.env.API_BASE_URL,
});

// Main function to start the stdio server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log startup information to stderr (stdout is reserved for MCP protocol)
  console.error('Insforge MCP server started');

  if (toolsConfig.apiKey) {
    console.error(`API Key: Configured`);
  } else {
    console.error('API Key: Not configured (will require api_key in tool calls)');
  }

  console.error(`API Base URL: ${toolsConfig.apiBaseUrl}`);
  console.error(`Tools registered: ${toolsConfig.toolCount}`);
  console.error(`process.cwd(): ${process.cwd()}`);
  console.error(`PWD env var: ${process.env.PWD || 'not set'}`);
  console.error(`HOME env var: ${process.env.HOME || 'not set'}`);

  // Try to request workspace roots from client
  // Note: McpServer may not have request() method in SDK v1.15.1
  // TODO: Investigate correct API for server-to-client requests
  try {
    console.error('Attempting to request workspace roots from client...');

    // Access the underlying server if available
    const serverInternal = (server as any).server || (server as any)._server;

    if (serverInternal && typeof serverInternal.request === 'function') {
      const rootsResult = await serverInternal.request(
        { method: 'roots/list' },
        {} as any
      );

      console.error('Roots response:', JSON.stringify(rootsResult));

      if (rootsResult && Array.isArray((rootsResult as any).roots)) {
        const roots = (rootsResult as any).roots
          .map((root: any) => {
            const uri = root.uri || '';
            return uri.replace('file://', '');
          })
          .filter(Boolean);

        setWorkspaceRoots(roots);

        if (roots.length > 0) {
          console.error(`✓ Workspace roots available: ${roots.join(', ')}`);
        } else {
          console.error('⚠ No workspace roots returned by client');
        }
      }
    } else {
      console.error('⚠ Server does not have request method available');
    }
  } catch (error) {
    console.error('⚠ Could not get workspace roots from client');
    console.error('  Error:', error instanceof Error ? error.message : String(error));
  }
}

main().catch(console.error);