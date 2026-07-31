import type { Response } from 'express';
import { renderOAuthErrorPage } from './templates/oauth-error.js';
import { SERVER_CONFIG, STREAMABLE_HTTP_ENDPOINTS } from './config.js';

/**
 * Sending an OAuth error to whoever is actually looking at it.
 *
 * `/oauth/authorize` and `/oauth/callback` are reached by a browser
 * navigation. The MCP client never reads those responses — it is waiting on a
 * loopback callback that will now never arrive — so the only party who sees an
 * error body is the person staring at the tab.
 *
 * #74 added a page saying what to do, and wired it to exactly one branch: the
 * unknown client_id. Every other way authorize can fail kept returning raw
 * OAuth JSON to that same tab. The one a user is most likely to hit — a
 * redirect_uri that does not match the registration — was among them, so the
 * live failure mode on the deployed server shows `{"error":"invalid_request"}`
 * and no instruction at all.
 *
 * That is the same shape of mistake as normalising a trailing slash at two of
 * ten consumers. So this is a helper every browser-reachable error goes
 * through, not a second patched branch.
 */

/**
 * The one thing this needs from a request. Narrower than express's Request on
 * purpose: the negotiation is the whole logic, and a two-line stand-in in a
 * test is worth more than a full Request mock nobody reads.
 */
export interface AcceptNegotiable {
  accepts(types: string[]): string | false;
}

export interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

export interface HumanForm {
  heading: string;
  message: string;
  /** Optional literal(s) the user should run, rendered as code. */
  action?: string | string[];
}

/**
 * The command that actually repairs one of these users.
 *
 * NOT `npx @insforge/install`, which is what this page said until Max traced
 * where the connected clients came from. There are two install paths and they
 * produce different products:
 *
 *   npx @insforge/install   installs @insforge/mcp as a LOCAL stdio server with
 *                           an API key. Never contacts this server at all.
 *   npx add-mcp <url>       adds the REMOTE server — server.json remotes[], and
 *                           what the setup docs tell people to run.
 *
 * Everyone who can possibly SEE this page arrived over the remote URL, because
 * this page is served by the remote server. So the old instruction was wrong
 * one hundred percent of the time, not merely sometimes — and following it
 * would have quietly moved someone onto a different product configuration
 * rather than fixing the one they had.
 *
 * TWO commands, not one, and that is the part measured rather than assumed.
 * Blair read add-mcp@2.0.0: writeJsonConfig deep-merges under the server key
 * and byte-preserves everything else, and the key is inferred from the
 * hostname. So on a SAME-hostname cutover `add-mcp <url>` writes an entry
 * identical to the one already there and changes nothing — the stuck user runs
 * it, fails identically, and opens a ticket. Removing first is what makes the
 * instruction do something.
 *
 * Correct on both roads, which is why it does not wait on the hostname
 * decision: on a new hostname the removal clears the stale entry you wanted
 * gone anyway; on the same hostname it is the only thing that helps. I checked
 * `remove <query>` exists with -y in that version rather than trusting the
 * name, and that the package stores no tokens of its own (its single "oauth"
 * reference is an oauthScopes CONFIG field).
 *
 * What this still cannot promise: whether removing the config entry also drops
 * the client's saved OAuth registration is client-specific — add-mcp deletes
 * its config key and nothing more. If some client keys its registration by
 * server name rather than URL, even remove+add leaves it stuck. That is a real
 * test on a real editor, not something to settle in a comment.
 *
 * Built from publicUrl, which is the CANONICAL host this deployment is
 * configured to be — deliberately not the host the request arrived on. The Host
 * header is attacker-controlled, and a page that echoed it would hand a
 * stuck user a command pointing wherever the attacker liked. Same reason the
 * discovery documents use publicUrl (server.ts, "to avoid host header
 * spoofing").
 *
 * Do not "fix" this to use the requested host. Today one deployment serves one
 * hostname so the two coincide and nothing distinguishes them; the moment a
 * retired hostname is pointed at a live deployment they diverge, and the
 * requested-host reading tells someone stuck on the dead host to re-add the
 * dead host. That is a loop with no exit, aimed at exactly the users a cutover
 * exists to rescue.
 *
 * Note for anyone planning that retired-hostname setup: it does not work by
 * itself, and not because of this function. A client reaching an old host whose
 * publicUrl is the NEW host gets a protected-resource document naming a
 * different origin, and the SDK throws in selectResourceURL
 * (client/auth.js:339) BEFORE it ever opens the browser — so this page is
 * never reached. Measured, not inferred.
 */
export function reconnectCommand(mcpUrl: string): string[] {
  // Remove BY URL, not by name. The name is derived from the hostname, so a
  // hardcoded "insforge" matches nothing on any host that infers a different
  // key — including the Manufact slug we spent a day testing on:
  //
  //   mcp.insforge.dev                   -> key "insforge"
  //   keen-pulse-fsjr9.run.mcp-use.com   -> key "keen-pulse-fsjr9"
  //
  // I made the ADD step host-derived and left the REMOVE step hardcoded, which
  // is the same inconsistency in one function. Max caught it.
  //
  // The URL works because add-mcp's findMatchingServers matches
  // `server.identity === query` as well as by name, and extractServerIdentity
  // returns the server's url for a remote entry (add-mcp@2.0.0,
  // chunk-2LJORNPV.js). So passing the URL is exact, host-derived by
  // construction, and cannot drift the way a copy of their inference rule
  // would.
  return [`npx add-mcp remove ${mcpUrl} -y`, `npx add-mcp ${mcpUrl}`];
}

/**
 * What to tell a person, given the machine-readable error.
 *
 * Pure and exported so the wording is testable without standing up express —
 * the part that matters here is the words, and they are the part a route test
 * would be least likely to assert.
 */
export function humanFormOf(body: OAuthErrorBody, mcpUrl: string): HumanForm {
  switch (body.error) {
    case 'invalid_client':
      return {
        heading: 'This connection needs to be set up again',
        message:
          'The app you are connecting from is not registered with this server any more. ' +
          'Nothing is wrong with your account and no data was lost — remove the InsForge MCP ' +
          'server from your client and add it back with the command below, and this will ' +
          'complete normally.',
        action: reconnectCommand(mcpUrl),
      };

    case 'invalid_request':
      // Overwhelmingly a redirect_uri that does not match the registration.
      // The remedy is identical to invalid_client — re-register — and the
      // cause is not something the person can inspect, so saying "invalid
      // request" and stopping would be true and useless.
      return {
        heading: 'This connection needs to be set up again',
        message:
          'The address your app asked us to send you back to is not the one it registered. ' +
          'That usually means the app was reinstalled or restarted on a different port. ' +
          'Re-adding the InsForge MCP server with the command below fixes it.',
        action: reconnectCommand(mcpUrl),
      };

    case 'server_error':
      return {
        heading: 'Something went wrong on our side',
        message:
          'This is not something you can fix by retrying the same way. If it keeps happening, ' +
          'the details below are what support will ask for.',
      };

    default:
      return {
        heading: 'Sign-in could not be completed',
        message:
          body.error_description ||
          'The sign-in did not complete. Removing the InsForge MCP server from your client ' +
          'and adding it back is the usual remedy.',
        action: reconnectCommand(mcpUrl),
      };
  }
}

/**
 * Is this request a browser navigation rather than a program's fetch?
 *
 * Kept here next to its only purpose. `req.accepts` returns the best match, so
 * a client sending `application/json` still gets JSON even though browsers
 * send a long Accept header that also mentions it.
 */
export function prefersHtml(req: AcceptNegotiable): boolean {
  return req.accepts(['json', 'html']) === 'html';
}

/**
 * Send an OAuth error as HTML to a browser and as JSON to everything else.
 *
 * The JSON body is unchanged in either case — a conforming client that does
 * read it still gets exactly what the spec says it should.
 */
export function sendOAuthError(
  req: AcceptNegotiable,
  res: Response,
  status: number,
  body: OAuthErrorBody,
  human?: Partial<HumanForm>
): Response {
  if (prefersHtml(req)) {
    const mcpUrl = `${SERVER_CONFIG.publicUrl}${STREAMABLE_HTTP_ENDPOINTS.mcp}`;
    return res
      .status(status)
      .type('html')
      .send(renderOAuthErrorPage({ ...humanFormOf(body, mcpUrl), ...human }));
  }
  return res.status(status).json(body);
}
