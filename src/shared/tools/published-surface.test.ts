import { describe, it, expect, vi } from 'vitest';
import { registerInsforgeTools } from './index.js';
import type { ToolHost } from './host.js';

/**
 * Tool names are the published contract.
 *
 * They come back in `tools/list` and people write them into agent prompts,
 * skills and documentation by name. Renaming one breaks every instruction
 * written against this server silently — the tool simply stops existing, and
 * nothing in the error points at the cause.
 *
 * The existing host tests check that every registered tool has a non-empty,
 * unique name. That passes just as happily after `run-raw-sql` becomes
 * `db-query`. This is the test that doesn't.
 *
 * A failure here is not a broken test. It means the published surface moved,
 * and the question is whether that was intended:
 *   - adding a tool          -> add it to the list, minor version
 *   - renaming or removing   -> breaking change, major version, and it needs
 *                               an alias and a deprecation window rather than
 *                               a rename in a PR
 */

// Registration refuses to start unless it can read the backend version, and the
// registered set is version-gated. A version above every gate is what makes
// this the FULL surface rather than whatever a particular backend allows.
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
          json: async () => ({ status: 'ok', version: '99.99.99', service: 'insforge' }),
        };
      }
      return actual.default(url, init);
    }),
  };
});

/**
 * The published tool surface as of @insforge/mcp 1.2.x.
 *
 * Sorted so the diff on a change is readable. Do not edit this to make a test
 * pass — edit it because you decided to change the contract.
 */
const SELF_HOSTED_TOOL_NAMES = [
  'bulk-upsert',
  'create-bucket',
  'create-deployment',
  'create-function',
  'delete-bucket',
  'delete-function',
  'download-template',
  'fetch-docs',
  'fetch-sdk-docs',
  'get-anon-key',
  'get-backend-metadata',
  'get-container-logs',
  'get-function',
  'get-table-schema',
  'list-buckets',
  'run-raw-sql',
  'update-function',
];

/**
 * Remote deliberately differs, and the difference is not arbitrary: a hosted
 * server cannot touch the user's filesystem, so the tools that read or write
 * local files are replaced by variants that hand the agent a command to run.
 *
 *   only self-hosted:  bulk-upsert      (reads a local filePath)
 *   only remote:       start-deployment (triggers the build after the agent
 *                                        has uploaded from its own machine)
 *
 * Both are published surfaces. Someone writing a prompt against
 * mcp.insforge.dev and someone writing one against the npm binary are writing
 * against different contracts, and both are contracts.
 */
const REMOTE_TOOL_NAMES = [
  'create-bucket',
  'create-deployment',
  'create-function',
  'delete-bucket',
  'delete-function',
  'download-template',
  'fetch-docs',
  'fetch-sdk-docs',
  'get-anon-key',
  'get-backend-metadata',
  'get-container-logs',
  'get-function',
  'get-table-schema',
  'list-buckets',
  'run-raw-sql',
  'start-deployment',
  'update-function',
];

/** The extra config the hosted server passes. */
const REMOTE = { mode: 'remote' as const, projectId: 'proj_1', accessToken: 'tok' };

async function registeredNames(extra?: Record<string, unknown>): Promise<string[]> {
  const names: string[] = [];
  const host: ToolHost = {
    registerTool(name) {
      names.push(name);
    },
  };
  await registerInsforgeTools(host, {
    apiKey: 'test-key',
    apiBaseUrl: 'http://localhost:7130',
    ...extra,
  });
  return names;
}

describe('published tool surface', () => {
  it('the npm binary registers exactly its documented names', async () => {
    const names = (await registeredNames()).sort();
    expect(names).toEqual(SELF_HOSTED_TOOL_NAMES);
  });

  it('the hosted server registers exactly its documented names', async () => {
    const names = (await registeredNames(REMOTE)).sort();
    expect(names).toEqual(REMOTE_TOOL_NAMES);
  });

  it('the two surfaces differ only where a hosted server cannot reach the filesystem', async () => {
    // Pinning the delta itself, so a tool quietly appearing in one mode and not
    // the other shows up as this test rather than as a support thread.
    const self = await registeredNames();
    const remote = await registeredNames(REMOTE);

    expect(self.filter((n) => !remote.includes(n)).sort()).toEqual(['bulk-upsert']);
    expect(remote.filter((n) => !self.includes(n)).sort()).toEqual(['start-deployment']);
  });

  it('names nothing twice, in either mode', async () => {
    // A duplicate silently shadows: the second registration wins and one tool
    // disappears from tools/list with no error anywhere.
    for (const cfg of [undefined, REMOTE]) {
      const names = await registeredNames(cfg);
      expect(new Set(names).size).toBe(names.length);
    }
  });
});
