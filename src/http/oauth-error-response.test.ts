import { describe, it, expect, vi } from 'vitest';
import { humanFormOf, prefersHtml, reconnectCommand, sendOAuthError } from './oauth-error-response.js';

const MCP_URL = 'https://mcp.insforge.dev/mcp';

/** Just enough of express's Request for the Accept negotiation. */
const asBrowser = { accepts: (types: string[]) => (types.includes('html') ? 'html' : false) };
const asClient = { accepts: (types: string[]) => (types.includes('json') ? 'json' : false) };

function mockResponse() {
  const res = {
    status: vi.fn(() => res),
    type: vi.fn(() => res),
    send: vi.fn(() => res),
    json: vi.fn(() => res),
  };
  return res as unknown as Parameters<typeof sendOAuthError>[1] & typeof res;
}

describe('who is actually looking at this error', () => {
  it('gives a browser HTML', () => {
    const res = mockResponse();
    sendOAuthError(asBrowser, res, 400, { error: 'invalid_request' });
    expect(res.type).toHaveBeenCalledWith('html');
    expect(res.json).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('gives a program the unchanged OAuth JSON', () => {
    // A conforming client that does read the body still gets exactly what the
    // spec says it should — the HTML is additive, not a replacement.
    const res = mockResponse();
    const body = { error: 'invalid_request', error_description: 'nope' };
    sendOAuthError(asClient, res, 400, body);
    expect(res.json).toHaveBeenCalledWith(body);
    expect(res.send).not.toHaveBeenCalled();
  });
});

describe('every browser-visible failure says what to do', () => {
  // #74 wired the page to exactly one branch, the unknown client_id. The one a
  // user is most likely to hit — a redirect_uri that does not match — kept
  // returning raw JSON. Patching that single branch would have repeated the
  // trailing-slash mistake, so this asserts the property over the codes.
  it.each([
    'invalid_client',
    'invalid_request',
    'server_error',
    'unsupported_response_type',
    'token_exchange_failed',
    'access_denied',
  ])('%s produces a heading and a message a person can act on', (error) => {
    const human = humanFormOf({ error }, MCP_URL);
    expect(human.heading.length).toBeGreaterThan(10);
    expect(human.message.length).toBeGreaterThan(40);
    // No machine vocabulary leaking into the sentence a person reads.
    expect(human.heading).not.toMatch(/_|redirect_uri|client_id/);
  });

  it('names the command that repairs a REMOTE client, not the local installer', () => {
    // These users arrived over the remote URL — that is the only way to reach
    // this page at all, since this server serves it. `npx @insforge/install`
    // installs a local stdio server with an API key: a different product, not
    // a repair. This page said that until it was traced.
    for (const error of ['invalid_client', 'invalid_request']) {
      const action = humanFormOf({ error }, MCP_URL).action as string[];
      expect(action).toEqual([
        'npx add-mcp remove insforge -y',
        'npx add-mcp https://mcp.insforge.dev/mcp',
      ]);
      expect(action.join(' ')).not.toContain('@insforge/install');
    }
  });

  it('removes before adding, so it is not a no-op on an unchanged URL', () => {
    // add-mcp deep-merges under the server key and byte-preserves the rest, and
    // the key is inferred from the hostname. So on a same-hostname cutover a
    // bare `add-mcp <url>` rewrites an identical entry and changes nothing:
    // the stuck user runs it, fails identically, and opens a ticket. Removing
    // first is what makes the instruction do something — and it is correct on
    // a new hostname too, where it clears the stale entry anyway.
    const [first, second] = reconnectCommand(MCP_URL);
    expect(first).toContain('remove');
    expect(second).toContain(MCP_URL);
  });

  it('names the host the person is actually talking to', () => {
    // On the Manufact slug it must say the slug, or someone follows the
    // instruction and reconnects to the box we are migrating off.
    expect(reconnectCommand('https://keen-pulse-fsjr9.run.mcp-use.com/mcp')).toEqual([
      'npx add-mcp remove insforge -y',
      'npx add-mcp https://keen-pulse-fsjr9.run.mcp-use.com/mcp',
    ]);
  });

  it('does not tell someone to reinstall when that would not help', () => {
    // A server-side failure is not fixed by re-adding the server, and saying so
    // would send a person round a loop that cannot terminate.
    expect(humanFormOf({ error: 'server_error' }, MCP_URL).action).toBeUndefined();
  });

  it('renders the redirect_uri case as the port-change it almost always is', () => {
    const human = humanFormOf({ error: 'invalid_request' }, MCP_URL);
    expect(human.message).toMatch(/different port/);
  });

  it('falls back to the description for a code it has never seen', () => {
    expect(humanFormOf({ error: 'weird_new_code', error_description: 'the disk melted' }, MCP_URL).message)
      .toBe('the disk melted');
  });

  it('still says something when there is no description either', () => {
    expect(humanFormOf({ error: 'weird_new_code' }, MCP_URL).message.length).toBeGreaterThan(40);
  });
});

describe('prefersHtml', () => {
  it('is false for a client asking for json', () => {
    expect(prefersHtml(asClient)).toBe(false);
  });

  it('is true for a browser', () => {
    expect(prefersHtml(asBrowser)).toBe(true);
  });
});
