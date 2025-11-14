import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { program } from 'commander';
import { registerInsforgeTools } from '../shared/tools.js';

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
}

main().catch(console.error);