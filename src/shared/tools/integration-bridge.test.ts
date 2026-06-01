import { describe, it, expect, beforeAll, vi } from 'vitest';
import { registerInsforgeTools } from './index.js';

vi.mock('node-fetch', async () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const actual = await vi.importActual('node-fetch') as any;
  return {
    default: vi.fn(async (url: string | URL, init?: any) => {
      if (url.toString().endsWith('/api/health')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'ok', version: '99.99.99', service: 'insforge' }),
        };
      }
      return actual.default(url, init);
    }),
  };
});

describe('MCP Integrated Testing Bridge', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registeredTools = new Map<string, any>();

  // Mock server to capture tools
  const mockServer = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    tool: (name: string, ...args: any[]) => {
      // The handler callback is always the final argument. Preceding args are
      // any combination of description (string), input schema (object), and
      // annotations (object), matching the SDK's `tool(...)` overloads.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cb: any = args[args.length - 1];
      const rest = args.slice(0, -1);

      const description = typeof rest[0] === 'string' ? (rest[0] as string) : '';
      const objectArgs = rest.filter((arg) => typeof arg === 'object' && arg !== null);
      // First object arg is the input schema; a second object arg (if any) is annotations.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const schema: any = objectArgs[0] ?? {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const annotations: any = objectArgs[1];

      registeredTools.set(name, { description, schema, annotations, cb });
      return mockServer;
    }
  };

  beforeAll(async () => {
    // API keys if provided from environment (Secrets)
    const apiKey = process.env.API_KEY || 'test-key';
    const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:7130';

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await registerInsforgeTools(mockServer as any, {
        apiKey,
        apiBaseUrl,
        mode: 'local'
      });
    } catch (e: any) {
      console.warn('Tool registration encountered warning (may be offline / unreachable backend):', e.message);
    }
  });

  it('should register tools correctly', () => {
    expect(registeredTools.size).toBeGreaterThan(0);
    expect(registeredTools.has('fetch-docs')).toBe(true);
  });

  it('should attach MCP annotations to registered tools', () => {
    // Read-only tool: should advertise readOnlyHint and a human-readable title.
    const fetchDocs = registeredTools.get('fetch-docs');
    expect(fetchDocs?.annotations).toBeDefined();
    expect(fetchDocs.annotations.title).toBe('Fetch Documentation');
    expect(fetchDocs.annotations.readOnlyHint).toBe(true);
    expect(fetchDocs.annotations.destructiveHint).toBe(false);

    // Destructive tool: run-raw-sql can run arbitrary SQL (incl. DROP).
    const runRawSql = registeredTools.get('run-raw-sql');
    expect(runRawSql?.annotations).toBeDefined();
    expect(runRawSql.annotations.readOnlyHint).toBe(false);
    expect(runRawSql.annotations.destructiveHint).toBe(true);

    // The handler must still be the captured callback, not the annotations object.
    expect(typeof fetchDocs.cb).toBe('function');
    expect(typeof runRawSql.cb).toBe('function');
  });

  it('should execute fetch-docs tool for instructions if credentials setup', async () => {
    const tool = registeredTools.get('fetch-docs');
    expect(tool).toBeDefined();

    const apiKey = process.env.API_KEY;
    if (!apiKey || apiKey === 'test-key') {
      console.warn('Skipping tool execution request verification (Missing API_KEY in env)');
      return;
    }

    try {
      const result = await tool.cb({ docType: 'instructions' });
      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(Array.isArray(result.content)).toBe(true);
      expect(result.isError).toBeFalsy();
    } catch (e) {
      console.error('Integration Execute fetch-docs failed:', e);
      throw e;
    }
  });

  it('should execute get-anon-key tool if supported', async () => {
    const tool = registeredTools.get('get-anon-key');
    if (!tool) return; // Might be skipped conditionally on Registration

    const apiKey = process.env.API_KEY;
    if (!apiKey || apiKey === 'test-key') return;

    try {
      const result = await tool.cb({});
      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.isError).toBeFalsy();
    } catch (e) {
      console.error('Integration Execute get-anon-key failed:', e);
      throw e;
    }
  });
});
