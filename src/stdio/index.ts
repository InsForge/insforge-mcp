import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { program } from 'commander';
import { PACKAGE_VERSION } from '../shared/version.js';
import { registerInsforgeTools } from '../shared/tools/index.js';
import { sdkToolHost } from '../shared/tools/host.js';

// Parse command line arguments
program
  .name('insforge-mcp')
  .description('MCP server for Insforge backend-as-a-service')
  .version(PACKAGE_VERSION, '-v, --version')
  .option('--api_key <value>', 'API Key')
  .option('--api_base_url <value>', 'API Base URL');
program.parse(process.argv);
const options = program.opts();
const { api_key, api_base_url } = options;

// Main function to start the stdio server
async function main() {
  // Create MCP server
  const server = new McpServer({
    name: 'insforge-mcp',
    version: PACKAGE_VERSION,
  });

  // Register all Insforge tools with the server (async to support dynamic version-based registration)
  const toolsConfig = await registerInsforgeTools(sdkToolHost(server), {
    apiKey: api_key,
    apiBaseUrl: api_base_url || process.env.API_BASE_URL,
    mode: 'local',
  });

  // Connect to transport AFTER tool registration is complete
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
  if (toolsConfig.backendVersion) {
    console.error(`Backend Version: ${toolsConfig.backendVersion}`);
  }
  console.error(`Tools registered: ${toolsConfig.toolCount}`);
}

main().catch(console.error);
