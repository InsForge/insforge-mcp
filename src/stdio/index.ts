import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { program } from 'commander';
import { registerInsforgeTools } from '../shared/tools/index.js';

// Parse command line arguments
program.option('--api_key <value>', 'API Key');
program.option('--api_base_url <value>', 'API Base URL');
program.parse(process.argv);
const options = program.opts();
const { api_key, api_base_url } = options;

// Main function to start the stdio server
async function main() {
  // Create MCP server
  const server = new McpServer({
    name: 'insforge-mcp',
    version: '1.0.0',
  });

  // Register all Insforge tools with the server (async to support dynamic version-based registration)
  const toolsConfig = await registerInsforgeTools(server, {
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