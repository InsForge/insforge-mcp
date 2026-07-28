import { describe, it, expect, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { sdkToolHost, type ToolHost } from './host.js';
import { registerInsforgeTools } from './index.js';

// registerInsforgeTools refuses to start unless it can read the backend version,
// so every case below decides which version /api/health reports.
let backendVersion = '99.99.99';

vi.mock('node-fetch', async () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const actual = (await vi.importActual('node-fetch')) as any;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    default: vi.fn(async (url: string | URL, init?: any) => {
      if (url.toString().endsWith('/api/health')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'ok', version: backendVersion, service: 'insforge' }),
        };
      }
      return actual.default(url, init);
    }),
  };
});

/** Host that records what the tool layer asked to register. */
function recordingHost() {
  const calls: Array<{
    name: string;
    description: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    inputSchema: Record<string, any>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    handler: (...args: any[]) => any;
  }> = [];

  const host: ToolHost = {
    registerTool(name, description, inputSchema, handler) {
      calls.push({ name, description, inputSchema, handler });
    },
  };

  return { host, calls };
}

describe('sdkToolHost', () => {
  // Against a real McpServer, not a hand-shaped stub: a stub can agree with an
  // assumption the SDK doesn't hold, which is exactly how the earlier
  // duck-typed asToolHost() passed its tests while being broken.
  it('registers a tool that a client can list and call', async () => {
    const server = new McpServer({ name: 'test', version: '1.0.0' });

    sdkToolHost(server).registerTool(
      'echo-tool',
      'echoes what it is given',
      { phrase: z.string().describe('what to echo') },
      async ({ phrase }: { phrase: string }) => ({
        content: [{ type: 'text' as const, text: `echo: ${phrase}` }],
      })
    );

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['echo-tool']);
    expect(tools[0].description).toBe('echoes what it is given');
    expect(tools[0].inputSchema.properties).toHaveProperty('phrase');

    const result = await client.callTool({ name: 'echo-tool', arguments: { phrase: 'hi' } });
    expect(result.content).toEqual([{ type: 'text', text: 'echo: hi' }]);

    await client.close();
    await server.close();
  });
});

describe('registerInsforgeTools through a ToolHost', () => {
  it('hands every tool over as (name, description, schema, handler)', async () => {
    backendVersion = '99.99.99';
    const { host, calls } = recordingHost();

    const result = await registerInsforgeTools(host, {
      apiKey: 'test-key',
      apiBaseUrl: 'http://localhost:7130',
    });

    expect(calls.length).toBe(result.toolCount);
    expect(calls.length).toBeGreaterThan(0);

    for (const call of calls) {
      expect(typeof call.name).toBe('string');
      expect(call.name.length).toBeGreaterThan(0);
      expect(typeof call.description).toBe('string');
      expect(call.description.length).toBeGreaterThan(0);
      expect(typeof call.inputSchema).toBe('object');
      expect(typeof call.handler).toBe('function');
    }

    // No tool registered twice — the conditional variants (create-deployment,
    // download-template, create-function, update-function) must resolve to one.
    const names = calls.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('registers the full surface onto a real SDK server', async () => {
    backendVersion = '99.99.99';
    const server = new McpServer({ name: 'insforge-mcp', version: 'test' });

    const result = await registerInsforgeTools(sdkToolHost(server), {
      apiKey: 'test-key',
      apiBaseUrl: 'http://localhost:7130',
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const { tools } = await client.listTools();
    expect(tools.length).toBe(result.toolCount);
    expect(tools.map((t) => t.name)).toContain('fetch-docs');
    for (const tool of tools) {
      expect(tool.description?.length).toBeGreaterThan(0);
      expect(tool.inputSchema.type).toBe('object');
    }

    await client.close();
    await server.close();
  });

  it('still applies backend-version gating at the seam', async () => {
    backendVersion = '1.4.6'; // one below create-deployment's 1.4.7 minimum
    const { host, calls } = recordingHost();

    await registerInsforgeTools(host, {
      apiKey: 'test-key',
      apiBaseUrl: 'http://localhost:7130',
    });

    const names = calls.map((c) => c.name);
    expect(names).not.toContain('fetch-sdk-docs'); // requires 1.5.1
    expect(names).toContain('fetch-docs'); // no version requirement
  });

  it('still skips local-only tools in remote mode', async () => {
    backendVersion = '99.99.99';
    const local = recordingHost();
    const remote = recordingHost();

    await registerInsforgeTools(local.host, {
      apiKey: 'test-key',
      apiBaseUrl: 'http://localhost:7130',
      mode: 'local',
    });
    await registerInsforgeTools(remote.host, {
      apiKey: 'test-key',
      apiBaseUrl: 'http://localhost:7130',
      mode: 'remote',
    });

    expect(local.calls.map((c) => c.name)).toContain('bulk-upsert');
    expect(remote.calls.map((c) => c.name)).not.toContain('bulk-upsert');
  });
});
