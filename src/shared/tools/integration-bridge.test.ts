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
          json: async () => ({ status: 'ok', version: '1.5.0', service: 'insforge' }),
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
      let description = '';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let schema: any = {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let cb: any;

      if (args.length === 1) {
        cb = args[0];
      } else if (args.length === 2) {
        if (typeof args[0] === 'string') {
          description = args[0];
          cb = args[1];
        } else {
          schema = args[0];
          cb = args[1];
        }
      } else if (args.length >= 3) {
        description = args[0];
        schema = args[1];
        cb = args[2];
      }

      registeredTools.set(name, { description, schema, cb });
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
    } catch (e) {
      console.error('Integration Execute get-anon-key failed:', e);
      throw e;
    }
  });
});
