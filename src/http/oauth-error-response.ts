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
 * AND THE ANSWER, which is no. Blair ran these commands as a stuck user
 * instead of reasoning about them: for Claude Code the saved authorisation
 * lives in `mcpOAuth` under `name|sha256(type,url,headers)`, a store add-mcp
 * never touches. Removing and re-adding the SAME url rebuilds the identical key
 * and picks the dead registration straight back up. So on an unchanged
 * hostname these commands do not repair anything on their own, and the page
 * used to promise "this will complete normally" — a promise that would have
 * been broken for exactly the population it was written for.
 *
 * The step that actually works is clearing the client's saved authorisation,
 * and it is client-specific:
 *
 *   Claude Code   /mcp -> pick the server -> Clear authentication   (a UI action)
 *   Codex         codex mcp logout insforge
 *
 * The Claude Code one is not a command, so it belongs in the sentence rather
 * than in a code block a person would try to paste. On a NEW hostname the
 * remove/add pair does repair by itself — different url, different key, no
 * saved state — so both are printed and the wording no longer claims more than
 * either can deliver.
 *
 * Still unverified, and stated rather than implied: nobody has watched a real
 * Claude Code reuse that record against a live server. Blair proved the record
 * survives the commands; the reuse is inferred from the key derivation.
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
  // TWO removes, not one, because a server can be defined in two scopes at
  // once and each command clears exactly one of them. From add-mcp@2.0.0's own
  // source:
  //
  //   program.command("remove <query>")
  //     .option("-g, --global", "Remove from global configs INSTEAD OF
  //                              project-level")
  //
  // "instead of" is the whole problem. Blair demonstrated the consequence on a
  // machine with the server defined in both places:
  //
  //   npx add-mcp remove <url> -y
  //     -> "Removed 1 server from 1 agent"      the project entry
  //     -> the user-level entry is STILL THERE
  //
  // So the page printed one command, the command reported success, and the
  // stuck user re-added and stayed stuck — with a cheerful confirmation that
  // the repair had worked. That is the same silent-partial-success shape this
  // page exists to end, committed by the page itself.
  //
  // Adding `-g` INSTEAD would not fix it either; it just moves which scope is
  // missed. The honest repair is both, and it is harmless to run either one
  // when that scope holds nothing — add-mcp reports zero removed and exits 0.
  return [
    'codex mcp logout insforge',
    `npx add-mcp remove ${mcpUrl} -y`,
    `npx add-mcp remove ${mcpUrl} -g -y`,
    `npx add-mcp ${mcpUrl}`,
  ];
}

/**
 * The step that actually clears a stuck client, in the words the page uses.
 *
 * One constant rather than a sentence copied into each branch. It has been
 * corrected three times now — the installer that was the wrong product, the
 * reconnect that repaired nothing on its own, the second remove for the scope
 * `-g` misses — and every correction had to find each copy. The branch below
 * that nobody remembered to update is what this constant exists to prevent.
 *
 * DO NOT simplify this to "remove the server and add it back". That reads as
 * the friendlier instruction and it repairs nothing. Quinn traced the shipped
 * Claude Code v2.1.220 binary: the menu action reaches
 * `clearServerTokensFromLocalStorage` with `preserveClientRegistration` falsy,
 * which deletes the whole `mcpOAuth` record including `clientId` — that is why
 * the TUI step is a real repair. The two substitutes a person would reach for
 * instead are not. `claude mcp remove` calls the same function behind a catch
 * that swallows its failure, and both records survive it (measured on seeded
 * files in an isolated HOME). `npx add-mcp remove` cannot help in principle: it
 * writes `~/.mcp.json`, and the OAuth record lives in `~/.claude.json`.
 *
 * So of the three remedies a stuck user might try, exactly one clears anything,
 * and it is the one that cannot be pasted from a code block.
 */
const CLEARING_INSTRUCTION =
  'In Claude Code: run /mcp, pick this server, and choose Clear authentication. In Codex: run ' +
  'the first command below. Then reconnect with the last one. Run the commands from the project ' +
  'directory where you use InsForge — one of them only looks there.';

/**
 * Terminate a sentence we did not write before another one follows it.
 *
 * The only text this is ever applied to is the platform's forwarded
 * `error_description`, which is outside our control and carries no punctuation
 * guarantee — "The user denied the request" is a real one. Joined with a bare
 * space it runs straight into the next sentence: "...denied the request In
 * Claude Code: run /mcp". Our own literal fallbacks end in a full stop, which
 * is exactly why the seam was invisible until Blair read the rendered copy.
 */
function endsSentence(text: string): string {
  const trimmed = text.trim();
  return /[.!?:;]$/.test(trimmed) ? trimmed : `${trimmed}.`;
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
        heading: 'Your client is holding a sign-in that no longer works',
        message:
          'Nothing is wrong with your account and no data was lost. Your editor has saved an ' +
          'authorisation for this server that this server no longer recognises, and it will keep ' +
          'reusing it until you clear it. ' +
          CLEARING_INSTRUCTION,
        action: reconnectCommand(mcpUrl),
      };

    case 'invalid_request':
      // Overwhelmingly a redirect_uri that does not match the registration.
      // The remedy is identical to invalid_client — re-register — and the
      // cause is not something the person can inspect, so saying "invalid
      // request" and stopping would be true and useless.
      return {
        heading: 'Your client is holding a sign-in that no longer works',
        message:
          'The address your app asked us to send you back to is not the one it registered — ' +
          'usually because it restarted on a different port. Clearing the saved authorisation is ' +
          'what fixes it. ' +
          CLEARING_INSTRUCTION,
        action: reconnectCommand(mcpUrl),
      };

    case 'server_error':
      return {
        heading: 'Something went wrong on our side',
        message:
          'This is not something you can fix by retrying the same way. If it keeps happening, ' +
          'the details below are what support will ask for.',
      };

    case 'access_denied':
      // Nothing is stale here — they cancelled. Clearing the authorisation
      // would destroy a registration that works and land them back on the same
      // consent screen, so this branch exists to keep the repair instruction
      // away from the one code we know does not need it.
      //
      // Reachable on exactly one path, and the flip makes it likelier rather
      // than rarer: /oauth/callback bounces a platform error back to the
      // client's own redirect_uri when it can open the auth state, and only
      // renders this page when it cannot (server.ts). A cancel whose state
      // cookie is missing or host-scoped to the other hostname is precisely
      // what a cutover window produces.
      //
      // Copy is Blair's, who caught that the default branch was pinning the
      // wrong remedy here.
      return {
        heading: 'You cancelled this sign-in',
        message: 'You cancelled the sign-in. Start it again and approve to continue.',
      };

    default:
      // The branch #101 did not reach, still telling people to remove the
      // server and add it back — the one remedy this file had already measured
      // as a no-op, printed under the commands that cannot carry it out. An
      // unknown code is not a reason to give worse advice than a known one, and
      // this branch is reachable: /oauth/callback forwards the PLATFORM's error
      // code verbatim (server.ts) when there is no registered redirect to bounce
      // it back to, so the codes arriving here are ones we do not choose.
      //
      // The description, when the platform sent one, is kept and led with — it
      // is the only account of what actually failed. What changes is that it no
      // longer arrives without the step that makes the commands beneath it work.
      return {
        heading: 'Sign-in could not be completed',
        message: `${endsSentence(body.error_description || 'The sign-in did not complete.')} ${CLEARING_INSTRUCTION}`,
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
