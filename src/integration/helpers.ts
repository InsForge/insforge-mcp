import { expect } from 'vitest';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Shape of a single content item returned by an MCP tool handler. */
export interface ToolContentItem {
  type: string;
  text: string;
}

/** Shape of the result object returned by an MCP tool handler. */
export interface ToolResult {
  content?: ToolContentItem[];
  isError?: boolean;
}

/** Metadata captured for each registered tool. */
export interface RegisteredTool {
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cb: (...args: any[]) => Promise<ToolResult>;
}

// ---------------------------------------------------------------------------
// Mock MCP Server
// ---------------------------------------------------------------------------

/**
 * Create a lightweight mock of `McpServer` that captures every tool
 * registered via `server.tool(name, ...)`.
 *
 * Returns the mock server instance **and** the map of registered tools so
 * tests can look up handlers by name and invoke them directly.
 */
export function createMockServer(): {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  server: any;
  tools: Map<string, RegisteredTool>;
} {
  const tools = new Map<string, RegisteredTool>();

  const server = {
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

      tools.set(name, { description, schema, cb });
      return server;
    },
  };

  return { server, tools };
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

/**
 * Read an environment variable.  Throws immediately if the variable is
 * missing or empty, causing the suite to fail in `beforeAll`.
 */
export function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(
      `Missing required environment variable: ${name}. ` +
        'Set it before running the real-project integration tests.',
    );
  }
  return value.trim();
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/** Common error-like patterns that indicate a failed response payload. */
const ERROR_PATTERNS: RegExp[] = [
  /^Error[:\s]/i,             // text starting with "Error:" or "Error "
  /"error"\s*:/i,             // JSON-like `"error":` key
  /\bUnauthorized\b/i,
  /\bForbidden\b/i,
  /\bInternal Server Error\b/i,
  /\bBad Request\b/i,
  /\bNot Found\b/i,           // explicit 404-style messages
];

/**
 * Assert that a tool is present in the registered tools map.
 * Fails the test with a descriptive message if the tool is missing.
 */
export function expectToolRegistered(
  tools: Map<string, RegisteredTool>,
  name: string,
): void {
  expect(
    tools.has(name),
    `Expected tool "${name}" to be registered, but it was not found. ` +
      `Registered tools: ${[...tools.keys()].join(', ')}`,
  ).toBe(true);
}

/**
 * Perform **strict** success validation on a tool result:
 *
 * 1. `result` is defined
 * 2. `result.isError` is not `true`
 * 3. `result.content` is a non-empty array
 * 4. At least one content item has `type === "text"`
 * 5. That text item's `text` is a non-empty string
 * 6. The text does **not** resemble a known error payload
 *
 * Call this in every test **before** adding tool-specific assertions.
 */
export function expectToolSuccess(result: ToolResult): string {
  // 1 — defined
  expect(result, 'Tool result must be defined').toBeDefined();

  // 2 — not an error
  expect(
    result.isError,
    `Tool returned isError: true. Content: ${JSON.stringify(result.content)}`,
  ).not.toBe(true);

  // 3 — content array
  expect(
    Array.isArray(result.content),
    'result.content must be an array',
  ).toBe(true);
  expect(
    result.content!.length,
    'result.content must be a non-empty array',
  ).toBeGreaterThan(0);

  // 4 — at least one text item
  const textItem = result.content!.find((c) => c.type === 'text');
  expect(
    textItem,
    'result.content must contain at least one item with type "text"',
  ).toBeDefined();

  // 5 — non-empty text
  const text = textItem!.text;
  expect(typeof text, 'text content must be a string').toBe('string');
  expect(
    text.trim().length,
    'text content must be non-empty',
  ).toBeGreaterThan(0);

  // 6 — does not look like an error payload
  for (const pattern of ERROR_PATTERNS) {
    expect(
      pattern.test(text),
      `Tool text looks like an error payload (matched ${pattern}). Text: "${text.slice(0, 200)}"`,
    ).toBe(false);
  }

  return text;
}
