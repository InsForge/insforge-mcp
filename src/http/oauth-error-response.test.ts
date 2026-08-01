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
        'codex mcp logout insforge',
        `npx add-mcp remove ${MCP_URL} -y`,
        `npx add-mcp remove ${MCP_URL} -g -y`,
        'npx add-mcp https://mcp.insforge.dev/mcp',
      ]);
      expect(action.join(' ')).not.toContain('@insforge/install');
    }
  });

  it('clears the saved authorisation before reconnecting', () => {
    // add-mcp deep-merges under the server key and byte-preserves the rest, and
    // the key is inferred from the hostname. So on a same-hostname cutover a
    // bare `add-mcp <url>` rewrites an identical entry and changes nothing:
    // the stuck user runs it, fails identically, and opens a ticket. Removing
    // first is what makes the instruction do something — and it is correct on
    // a new hostname too, where it clears the stale entry anyway.
    // Blair ran these as a stuck user: on an unchanged hostname remove+add
    // rebuilds the SAME mcpOAuth key and picks the dead registration back up,
    // so the commands alone repair nothing. Clearing the client's saved
    // authorisation is the step that works, and it comes first.
    const [logout, removeProject, removeGlobal, add] = reconnectCommand(MCP_URL);
    expect(logout).toContain('logout');
    expect(removeProject).toContain('remove');
    // TWO removes: add-mcp's -g means "instead of project-level", not "as
    // well as", so one command clears one scope and reports success while the
    // other copy survives. Blair measured that on a machine with both.
    expect(removeGlobal).toContain('remove');
    expect(removeGlobal).toContain('-g');
    expect(add).toContain(MCP_URL);
  });

  it('does not promise the reconnect alone will work', () => {
    // The page used to say "add it back ... and this will complete normally".
    // On an unchanged hostname that promise is false for Claude Code, and it
    // was aimed at exactly the people it would fail.
    for (const error of ['invalid_client', 'invalid_request']) {
      const { message } = humanFormOf({ error }, MCP_URL);
      expect(message).not.toContain('complete normally');
      expect(message).toMatch(/Clear authentication/);
    }
  });

  // The property, over every code rather than over the two branches someone
  // remembered. The test above asserted the right thing about the wrong set:
  // it named `invalid_client` and `invalid_request` explicitly, so the default
  // branch went on telling people to remove the server and add it back — the
  // remedy this same file documents as a no-op — for as long as nobody looked.
  // A test that lists the cases it imagines stops covering the one it does not.
  //
  // Quinn traced why the distinction matters: only the Claude Code TUI action
  // deletes the mcpOAuth record. `claude mcp remove` swallows its own failure
  // and `npx add-mcp remove` writes a different file entirely, so commands
  // printed without the menu step leave the user in the loop the page exists
  // to end.
  it.each([
    ['invalid_client', undefined],
    ['invalid_request', undefined],
    ['unsupported_response_type', 'Only response_type=code is supported'],
    ['access_denied', undefined],
    ['access_denied', 'The user denied the request'],
    ['token_exchange_failed', undefined],
    ['weird_new_code', undefined],
    ['weird_new_code', 'the disk melted'],
  ])('%s (description: %s) never prints the commands without the step that makes them work', (error, error_description) => {
    const { message, action } = humanFormOf({ error, error_description }, MCP_URL);
    // Asserted, not guarded. This read `if (!action) return` — meant for
    // server_error, which is not in this table and so never reached it. What it
    // would actually have done is let a branch that silently LOST its commands
    // pass the test written to protect them: exactly the it-cannot-fail shape
    // that let the default branch drift in the first place. Caught in review by
    // john-bot and coderabbit independently.
    expect(action).toBeDefined();
    expect(message).toMatch(/Clear authentication/);
    // Broader than the one sentence that was removed. The defect was never that
    // phrasing — it was selling remove-and-re-add as the remedy, which reads as
    // the friendlier instruction in any wording someone reaches for next.
    expect(message).not.toMatch(/add(ing)? it back/i);
  });

  it('names the host the person is actually talking to, in BOTH commands', () => {
    // On the Manufact slug it must say the slug, or someone follows the
    // instruction and reconnects to the box we are migrating off.
    //
    // Both commands, because the removal used to hardcode "insforge" while the
    // add step was host-derived: on the slug the removal then matched no
    // server at all and the repair silently did nothing. add-mcp matches
    // `server.identity === query` and identity is the URL for a remote entry,
    // so passing the URL is exact on every host.
    const slug = 'https://keen-pulse-fsjr9.run.mcp-use.com/mcp';
    expect(reconnectCommand(slug)).toEqual([
      'codex mcp logout insforge',
      `npx add-mcp remove ${slug} -y`,
      `npx add-mcp remove ${slug} -g -y`,
      `npx add-mcp ${slug}`,
    ]);
    // The two add-mcp commands are host-derived; the codex one names the
    // server as that client stored it, which is our product name on any host.
    for (const command of reconnectCommand(slug).slice(1)) {
      expect(command).toContain('keen-pulse-fsjr9');
      expect(command).not.toContain('insforge.dev');
    }
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

  it('leads with the description for a code it has never seen', () => {
    // Deliberately no longer the description ALONE. It is the only account of
    // what actually failed, so it is kept and it comes first — but it used to
    // arrive with the reconnect commands and no way to make them work, which
    // is the same trap as the fallback sentence it sits beside.
    const { message } = humanFormOf(
      { error: 'weird_new_code', error_description: 'the disk melted' },
      MCP_URL
    );
    expect(message).toMatch(/^the disk melted/);
    expect(message).toMatch(/Clear authentication/);
  });

  it('still says something when there is no description either', () => {
    // The lead sentence and the repair, both — a length check alone passed
    // happily on the old text, whose 40+ characters were the no-op advice.
    const { message } = humanFormOf({ error: 'weird_new_code' }, MCP_URL);
    expect(message).toMatch(/^The sign-in did not complete\./);
    expect(message).toMatch(/Clear authentication/);
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

describe('the repair clears every scope it can live in', () => {
  /**
   * A server can be defined in two scopes at once, and add-mcp's remove clears
   * exactly one per invocation:
   *
   *   .option("-g, --global", "Remove from global configs INSTEAD OF
   *                            project-level")
   *
   * "instead of" is the defect. The page printed one remove, it reported
   * "Removed 1 server", and the other copy survived — so a stuck user
   * re-added and stayed stuck, told it had worked. Adding `-g` instead of the
   * plain form would only move which scope is missed.
   */

  const URL_ = 'https://keen-pulse-fsjr9.run.mcp-use.com/mcp';

  it('issues a remove for BOTH scopes, not one', () => {
    const removes = reconnectCommand(URL_).filter((c) => c.includes('remove'));
    expect(removes).toHaveLength(2);
    expect(removes.some((c) => !c.includes('-g'))).toBe(true);  // project scope
    expect(removes.some((c) => c.includes('-g'))).toBe(true);   // global scope
  });

  it('removes before it re-adds, in that order', () => {
    // Re-adding first would rebuild the entry the removal is meant to clear.
    const cmds = reconnectCommand(URL_);
    const lastRemove = cmds.map((c) => c.includes('remove')).lastIndexOf(true);
    const add = cmds.findIndex((c) => c.includes('add-mcp') && !c.includes('remove'));
    expect(add).toBeGreaterThan(lastRemove);
  });
});

describe('the page says where to run the commands', () => {
  /**
   * Project scope is CWD-relative, so both removes miss a project entry
   * written somewhere else. Blair measured it:
   *
   *   entry in ~/projA/.mcp.json, run from ~/projB
   *     remove <url> -y      "No matching servers found"
   *     remove <url> -g -y   "No matching servers found"
   *     projA entry          STILL THERE
   *
   * Both results are honest — there is nothing to remove where they looked —
   * and the user is still broken. That is the same silent-partial-success one
   * directory over, and the only fix available to a page is to say where to
   * stand. A sentence, not a command.
   */

  it('tells the reader which directory to run them from', () => {
    for (const error of ['invalid_client', 'invalid_request']) {
      const { message } = humanFormOf({ error }, MCP_URL);
      expect(message).toMatch(/project directory/);
    }
  });
});
