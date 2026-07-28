/**
 * Real-project integration tests — Phase 1 (read-only / low-risk tools).
 *
 * This suite executes MCP tools against a **live** Insforge backend.
 * It never mocks HTTP calls and enforces strict success semantics.
 *
 * Required environment variables (suite is skipped if missing):
 *
 *   INTEGRATION_TEST_ENABLED  = "true"
 *   INSFORGE_CLIENT_SECRET    — admin API key
 *   INSFORGE_API_BASE         — base URL of the live backend
 *   INTEGRATION_FUNCTION_SLUG — (Optional) slug of a stable fixture edge function
 *
 * Optional:
 *   INTEGRATION_LOG_SOURCE   — log source (default: "insforge.logs")
 */

import 'dotenv/config';
import { describe, it, expect, beforeAll } from 'vitest';
import { registerInsforgeTools } from '../shared/tools/index.js';
import { sdkToolHost } from '../shared/tools/host.js';
import {
  createMockServer,
  getRequiredEnv,
  expectToolRegistered,
  expectToolSuccess,
  type RegisteredTool,
} from './helpers.js';

// ---------------------------------------------------------------------------
// Gate: skip the entire suite unless explicitly enabled
// ---------------------------------------------------------------------------
const integrationEnabled = process.env.INTEGRATION_TEST_ENABLED === 'true';

describe.skipIf(!integrationEnabled)('Real Project Integration Tests (Phase 1)', () => {
  // Registered tools populated once in beforeAll
  let tools: Map<string, RegisteredTool>;

  // Environment-driven configuration
  let API_KEY: string;
  let API_BASE_URL: string;
  let FUNCTION_SLUG: string;
  let LOG_SOURCE: string;

  // ------------------------------------------------------------------
  // Setup — validates env and registers tools against the real backend
  // ------------------------------------------------------------------
  beforeAll(async () => {
    // Validate required env vars (throws on missing, failing the suite)
    API_KEY = getRequiredEnv('INSFORGE_CLIENT_SECRET');
    API_BASE_URL = getRequiredEnv('INSFORGE_API_BASE');

    // Optional fixtures: skipped gracefully if missing
    FUNCTION_SLUG = process.env.INTEGRATION_FUNCTION_SLUG || '';

    LOG_SOURCE = process.env.INTEGRATION_LOG_SOURCE || 'insforge.logs';

    // Create a mock MCP server to capture tool registrations
    const { server, tools: registeredTools } = createMockServer();

    // Register tools — NO try/catch: a failure here must crash the suite
    await registerInsforgeTools(sdkToolHost(server), {
      apiKey: API_KEY,
      apiBaseUrl: API_BASE_URL,
      mode: 'local',
    });

    tools = registeredTools;
  });

  // ------------------------------------------------------------------
  // Smoke: verify that tool registration succeeded
  // ------------------------------------------------------------------
  it('should register all expected Phase 1 tools', () => {
    expect(tools.size, 'No tools were registered').toBeGreaterThan(0);

    const expectedTools = [
      'fetch-docs',
      'get-backend-metadata',
      'list-buckets',
      'get-container-logs',
      'get-function',
    ];

    for (const name of expectedTools) {
      expectToolRegistered(tools, name);
    }
  });

  // ------------------------------------------------------------------
  // fetch-docs
  // ------------------------------------------------------------------
  it('fetch-docs("instructions") should return substantial documentation', async () => {
    expectToolRegistered(tools, 'fetch-docs');
    const tool = tools.get('fetch-docs')!;

    const result = await tool.cb({ docType: 'instructions' });
    const text = expectToolSuccess(result);

    // The instructions document should be non-trivial
    expect(
      text.length,
      `Expected substantial documentation but got only ${text.length} characters`,
    ).toBeGreaterThan(50);
  });

  // ------------------------------------------------------------------
  // get-backend-metadata
  // ------------------------------------------------------------------
  it('get-backend-metadata should return backend metadata', async () => {
    expectToolRegistered(tools, 'get-backend-metadata');
    const tool = tools.get('get-backend-metadata')!;

    const result = await tool.cb({ apiKey: API_KEY });
    const text = expectToolSuccess(result);

    // The response text should contain the word "metadata" (case-insensitive)
    expect(
      text.toLowerCase(),
      'Expected metadata response to contain "metadata"',
    ).toContain('metadata');
  });

  // ------------------------------------------------------------------
  // list-buckets
  // ------------------------------------------------------------------
  it('list-buckets should return bucket listing successfully', async () => {
    expectToolRegistered(tools, 'list-buckets');
    const tool = tools.get('list-buckets')!;

    const result = await tool.cb({ apiKey: API_KEY });
    const text = expectToolSuccess(result);

    // The formatted success message includes a header like "Buckets retrieved"
    expect(
      text.toLowerCase(),
      'Expected bucket retrieval success indicator',
    ).toContain('bucket');
  });

  // ------------------------------------------------------------------
  // get-container-logs
  // ------------------------------------------------------------------
  it('get-container-logs should return log entries', async () => {
    expectToolRegistered(tools, 'get-container-logs');
    const tool = tools.get('get-container-logs')!;

    const result = await tool.cb({
      apiKey: API_KEY,
      source: LOG_SOURCE,
      limit: 5,
    });
    const text = expectToolSuccess(result);

    // The formatted success message includes a header like "Latest logs from insforge.logs"
    expect(
      text.toLowerCase(),
      'Expected log retrieval confirmation in response',
    ).toContain('log');
  });

  // ------------------------------------------------------------------
  // get-function
  // ------------------------------------------------------------------
  it('get-function should return details for the fixture function', async () => {
    if (!FUNCTION_SLUG) {
      console.warn('Skipping get-function test (INTEGRATION_FUNCTION_SLUG is not set)');
      return;
    }

    expectToolRegistered(tools, 'get-function');
    const tool = tools.get('get-function')!;

    const result = await tool.cb({ apiKey: API_KEY, slug: FUNCTION_SLUG });
    const text = expectToolSuccess(result);

    // The response must reference the slug we asked for
    expect(
      text,
      `Expected response to contain the fixture slug "${FUNCTION_SLUG}"`,
    ).toContain(FUNCTION_SLUG);
  });

  // ------------------------------------------------------------------
  // get-anon-key (optional — only runs if the tool was registered)
  // ------------------------------------------------------------------
  it('get-anon-key should return a token if the tool is registered', async () => {
    if (!tools.has('get-anon-key')) {
      // Tool may not be registered depending on backend version; skip gracefully
      return;
    }

    const tool = tools.get('get-anon-key')!;

    const result = await tool.cb({ apiKey: API_KEY });
    const text = expectToolSuccess(result);

    // Should contain some non-trivial token text
    expect(
      text.length,
      'Expected non-trivial token response',
    ).toBeGreaterThan(10);
  });
});
