import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/**
 * The only thing the tool layer needs from a server: somewhere to put a tool.
 *
 * Every tool in src/shared/tools registers with the same four arguments — name,
 * description, a zod raw shape, and a handler — so that is the contract here,
 * rather than the variadic overloads the MCP SDK happens to accept. Keeping the
 * seam explicit means a host for a different server implementation only has to
 * translate one call shape.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ToolInputSchema = Record<string, any>;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ToolHandler = (...args: any[]) => any;

export interface ToolHost {
  registerTool(
    name: string,
    description: string,
    inputSchema: ToolInputSchema,
    handler: ToolHandler
  ): void;
}

/**
 * Host backed by an MCP SDK server (both the stdio entrypoint and the current
 * HTTP session manager). Forwards positionally, which is what `server.tool`
 * expects for the (name, description, paramsSchema, cb) overload.
 */
export function sdkToolHost(server: McpServer): ToolHost {
  return {
    registerTool(name, description, inputSchema, handler) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (server.tool as any)(name, description, inputSchema, handler);
    },
  };
}

/**
 * Accept either a host or a bare SDK server, so callers that still pass a
 * server keep working. Anything exposing `registerTool` is taken as a host.
 */
export function asToolHost(target: McpServer | ToolHost): ToolHost {
  if (typeof (target as ToolHost).registerTool === 'function') {
    return target as ToolHost;
  }
  return sdkToolHost(target as McpServer);
}
