import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { program } from 'commander';
import { registerInsforgeTools } from '../shared/tools.js';

// Debug: Log environment variables to stderr for troubleshooting
console.error('=== Environment Debug ===');
console.error('API_KEY from env:', process.env.API_KEY ? 'Set (length: ' + process.env.API_KEY.length + ')' : 'Not set');
console.error('API_BASE_URL from env:', process.env.API_BASE_URL || 'Not set');
console.error('NODE_VERSION:', process.version);
console.error('=========================');

// Parse command line arguments
program.option('--api_key <value>', 'API Key');
program.option('--api_base_url <value>', 'API Base URL');
program.parse(process.argv);
const options = program.opts();
const { api_key, api_base_url } = options;

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