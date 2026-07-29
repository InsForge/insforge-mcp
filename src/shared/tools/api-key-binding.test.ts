import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerInsforgeTools } from './index.js';
import { sdkToolHost } from './host.js';

/**
 * In remote mode the project credential is bound to the session at sign-in.
 * Several tools also expose an optional `apiKey` argument, which exists for the
 * self-hosted stdio mode where the caller legitimately supplies its own
 * credential. Honouring that argument in remote mode would mean the session
 * credential is not authoritative — a caller could substitute any key it knows.
 *
 * These tests pin which key actually reaches the backend, per mode, by watching
 * the outgoing request rather than by reasoning about the closure.
 */

const SESSION_KEY = 'ik_bound_to_the_session';
const CALLER_KEY = 'ik_supplied_by_the_caller';

const sentKeys: string[] = [];

function keyOf(init?: { headers?: Record<string, string> }): string | undefined {
  return init?.headers?.['x-api-key'];
}

function reply(body: unknown, status = 200) {
  return {
    ok: status < 400,
    status,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

// The tool modules do `import fetch from 'node-fetch'`, so the global is never
// consulted — mocking it would silently test nothing.
vi.mock('node-fetch', () => ({
  default: vi.fn(async (input: unknown, init?: { headers?: Record<string, string> }) => {
    const url = String(input);
    if (url.endsWith('/api/health')) {
      return reply({ version: '1.2.0' });
    }
    const key = keyOf(init);
    if (key) sentKeys.push(key);
    return reply({ ok: true });
  }),
}));

beforeEach(() => {
  sentKeys.length = 0;
});

afterEach(() => {
  vi.clearAllMocks();
});

/** Fail loudly rather than silently testing a tool that has no apiKey argument. */
function requireTool(tools: Map<string, (args: any) => any>, name: string) {
  const tool = tools.get(name);
  if (!tool) throw new Error(`no tool named ${name}; got: ${[...tools.keys()].join(', ')}`);
  return tool;
}

/** Register against a real McpServer and return the callable tool map. */
async function toolsFor(mode: 'remote' | undefined) {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const captured = new Map<string, (args: any) => any>();
  const host = sdkToolHost(server);
  const spy = {
    registerTool(name: string, description: string, schema: any, handler: any) {
      captured.set(name, handler);
      host.registerTool(name, description, schema, handler);
    },
  };

  await registerInsforgeTools(spy, {
    apiKey: SESSION_KEY,
    apiBaseUrl: 'https://project.example.com',
    mode,
    projectId: 'proj_1',
    accessToken: 'tok',
  });

  return captured;
}

describe('which api key reaches the backend', () => {
  it('remote mode ignores a caller-supplied apiKey and uses the session credential', async () => {
    const tools = await toolsFor('remote');
    const tool = requireTool(tools, 'get-table-schema');

    await tool({ apiKey: CALLER_KEY, tableName: 't' }).catch(() => {});

    expect(sentKeys.length).toBeGreaterThan(0);
    expect(sentKeys).not.toContain(CALLER_KEY);
    expect(sentKeys.every((k) => k === SESSION_KEY)).toBe(true);
  });

  it('self-hosted mode still honours it, because that is how stdio is configured', async () => {
    // Not a bug there: the operator running the binary supplies the key.
    const tools = await toolsFor(undefined);
    const tool = requireTool(tools, 'get-table-schema');

    await tool({ apiKey: CALLER_KEY, tableName: 't' }).catch(() => {});

    expect(sentKeys).toContain(CALLER_KEY);
  });

  it('remote mode with no argument at all is unchanged', async () => {
    const tools = await toolsFor('remote');
    const tool = requireTool(tools, 'get-table-schema');

    await tool({ tableName: 't' }).catch(() => {});

    expect(sentKeys.every((k) => k === SESSION_KEY)).toBe(true);
  });
});
