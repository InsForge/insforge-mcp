import { createHash } from 'crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { SESSION_SWEEP_MS } from './config.js';
import { registerInsforgeTools } from '../shared/tools/index.js';
import { sdkToolHost } from '../shared/tools/host.js';
import { PACKAGE_VERSION } from '../shared/version.js';

/**
 * A session id, safe to log.
 *
 * An existing session is served without a token check — Mcp-Session-Id alone
 * yields the stored project key and full tool access — so it is a bearer
 * credential and belongs in a log the way a token does: not at all. Manufact
 * serves its runtime logs over an API, which makes a raw id there a live
 * credential at rest rather than a routing breadcrumb.
 *
 * Deterministic, so the same session prints the same value at every site and a
 * support report still correlates. Same construction as server.ts’s
 * tokenFingerprint, deliberately: two equivalent credentials, one treatment.
 */
export function sessionFingerprint(sessionId: string | undefined | null): string {
  return sessionId ? createHash('sha256').update(sessionId).digest('hex').substring(0, 8) : 'none';
}

/**
 * Sessions, and the honest limit of "stateless".
 *
 * Every other piece of state in this server became a value: a client
 * registration is a signed id, an authorization state is a sealed cookie, an
 * authorization code and an access token are sealed envelopes. All of them were
 * derived data pretending to be storage, so carrying them in the artefact that
 * travels removed the store entirely.
 *
 * A session is NOT that, and it is worth being exact about why rather than
 * finishing the sweep and calling the server stateless.
 *
 * An MCP session owns an `McpServer` and a live `StreamableHTTPServerTransport`
 * — a registered tool set and, for a streaming client, an OPEN TCP CONNECTION
 * held by one process. A connection cannot be sealed into a token, because the
 * thing being persisted is not information: it is a socket. No amount of
 * cryptography moves it to another machine.
 *
 * So Redis was never making sessions stateless either. It stored a copy of the
 * data BESIDE the connection, and `restoreSession` rebuilt a new server and
 * transport around a REUSED session id. That works only for a client that
 * reconnects with a POST, which is also precisely the client that could just as
 * well re-initialize. It bought us:
 *
 *   a session id surviving a restart      real, but only for POSTing clients
 *   sharing sessions across instances     never used: one instance, and the
 *                                         transport is not shareable anyway
 *   an expiry clock                       replaced here by the idle sweep
 *
 * against a hard dependency in the request path of every tool call. That is a
 * bad trade at one instance, and it is the last thing keeping Redis alive.
 *
 * WHAT THIS COSTS, stated plainly: a restart drops every live session. The
 * client's recovery is to see 404 on its session id and initialize again — the
 * protocol's own answer, and what the SDK's own server does. It is a real
 * regression for anyone mid-stream, and it is the price of the dependency going
 * away. If we later run more than one instance, the answer is sticky routing or
 * a shared transport layer, NOT a session copy in Redis: that copy never made
 * the connection portable.
 */

/**
 * The data half of a session — everything a rebuilt tool registry needs.
 * Kept as its own type because it is the part that IS just information; the
 * runtime half beside it is not.
 */
export interface SessionData {
  // Core configuration for MCP tools
  apiKey: string;
  apiBaseUrl: string;

  // Project information
  projectId: string;
  projectName: string;

  // User and organization
  userId: string;
  organizationId: string;

  // OAuth token hash for validation
  oauthTokenHash: string;

  // Metadata
  createdAt: number;
  lastAccessedAt: number;
  backendVersion?: string;
}

/**
 * One session: the live instances, and the data that describes them.
 *
 * These used to live in two places — instances in a Map, data in Redis — and
 * the split was the source of every subtlety in the sweep below, because the
 * two halves could disagree about whether a session existed. One entry cannot
 * disagree with itself.
 */
interface RuntimeSession {
  server: McpServer;
  transport: StreamableHTTPServerTransport | SSEServerTransport;
  transportType: 'streamable' | 'sse';
  data: SessionData;
  // Last time this process saw real client traffic for the session, on the
  // monotonic clock. This is now the ONLY clock: it decides when an idle
  // session is collected.
  lastSeenAt: number;
  // Server->client streams currently open for this session (GET /mcp). A stream
  // is activity that leaves no other trace: it produces no requests, so nothing
  // stamps lastSeenAt for as long as it stays open.
  openStreams: number;
}

// How long a session survives with no traffic and no open stream (24 hours).
const SESSION_TTL = 24 * 60 * 60;

// Session TTL in milliseconds, for comparison against in-memory timestamps.
export const SESSION_TTL_MS = SESSION_TTL * 1000;

/**
 * Clock for in-memory session ages.
 *
 * Deliberately monotonic rather than Date.now(). These timestamps are only
 * ever compared against each other to measure elapsed time, never against
 * anything Redis stores, so wall-clock accuracy buys nothing — while a
 * forward clock step (NTP correction, a VM resuming from suspend) would age
 * every live session past its TTL at once and hand the sweep the exact
 * conclusion this gate exists to prevent. CLOCK_MONOTONIC can only lag real
 * elapsed time, which errs toward holding a session too long.
 */
export function monotonicNow(): number {
  return performance.now();
}

/** The sweep's view of one runtime session. */
export interface SweepCandidate {
  sessionId: string;
  lastSeenAt: number;
  openStreams: number;
}

/**
 * Pick the sessions that have gone idle for longer than the TTL.
 *
 * This used to take a second argument: the pipelined EXISTS reply saying
 * whether Redis still held a record. Every subtlety it carried came from having
 * two clocks that could disagree —
 *
 *   Redis expires a record early (restart, cold failover, eviction) and every
 *   resident session reads as an orphan at once, so the sweep closes live
 *   connections. The in-memory clock was the gate that stopped it.
 *
 * — and with one clock there is nothing to disagree with. The gate that
 * remains is the one that was doing the real work all along: a session is
 * collectable when nobody has talked to it for SESSION_TTL_MS.
 *
 * Deleting the `exists` term is therefore not a loosening. It removes the
 * failure mode it was written to defend against, and what is left is strictly
 * the stricter of the two conditions.
 *
 * An open server->client stream still counts as alive on its own, and that part
 * is NOT redundant. It is the one form of activity that stamps no clock: the
 * client holds GET /mcp open and may send no requests at all, so lastSeenAt
 * stays frozen at the moment the stream opened while the client is plainly
 * still connected.
 */
/**
 * May this request use this session?
 *
 * A session id alone is enough to be routed to a live session: routing decides
 * before any credential is read, deliberately, so that a dead id gets its 404
 * without a login. The consequence is that `Mcp-Session-Id` is a bearer
 * credential — it yields the stored project key and full tool access — and one
 * leaked id is read and write on someone else's project. Fingerprinting the id
 * out of the logs stops us writing it down; this stops a copy that escaped
 * anyway from being used.
 *
 * Deliberately NOT a second authentication. It asks one question: was this
 * session opened with an OAuth token, and is the caller presenting the same
 * one? A session with nothing to bind to is accepted unchanged —
 *
 *   'legacy'  an x-api-key session. Its credential is the header it re-sends on
 *             every request; there is no token to compare.
 *   ''        an SSE path that stores no hash.
 *
 * Rejecting those would log out every legacy client the moment this deploys,
 * which is why the question is "was something bound" rather than "the hashes
 * must match".
 *
 * SAFE AGAINST A MID-SESSION LOGOUT, and that is measured rather than hoped:
 * the SDK's `_commonHeaders()` sets `Authorization` and `mcp-session-id` in one
 * place, and all three request paths use it (`send`, `_startOrAuthSse`,
 * `terminateSession`). Driven against a real client, every POST carried the
 * token — initialize, the initialized notification, and each tools/list — so a
 * client that had a token on request one still has it on request two.
 *
 * BOTH HASHES MUST BE THE FULL-LENGTH FORM. `SessionData.oauthTokenHash` is a
 * 64-character sha256 from oauth-manager's `hashToken`; server.ts also has a
 * `tokenFingerprint` that is the FIRST 8 CHARACTERS, for logs. Comparing one
 * against the other rejects every OAuth session on its second request — a
 * mid-session logout for everyone, arriving through the door this function
 * exists to keep shut. Quinn hit exactly that writing the first version.
 *
 * The caller must apply this INSIDE the branch that has already found a live
 * session. Applied before routing it would authenticate first, and a client
 * with a dead session plus a stale token would get 401 where it needs the 404
 * that tells it to start over.
 */
export function sessionAcceptsCredential(
  storedTokenHash: string | undefined,
  presentedTokenHash: string | undefined
): boolean {
  // Nothing was bound at creation: an x-api-key session, or a path that stores
  // no hash. Unchanged behaviour for those, on purpose.
  if (!storedTokenHash || storedTokenHash === 'legacy') return true;
  return presentedTokenHash === storedTokenHash;
}

export function selectOrphanedSessions(
  sessions: SweepCandidate[],
  now: number = monotonicNow()
): string[] {
  return sessions
    .filter(
      (session) => session.openStreams === 0 && now - session.lastSeenAt >= SESSION_TTL_MS
    )
    .map((session) => session.sessionId);
}

/** What POST /mcp should do with a request, given what we hold. */
export type SessionRoute =
  /** We have the session: reuse its transport. */
  | 'use-existing'
  /** A session id we do not hold -> 404, so the client starts a new session. */
  | 'not-found'
  /** An initialize request: make a new session. */
  | 'create'
  /** No session id and not an initialize -> 400, nothing to route to. */
  | 'no-session';

/**
 * The branch order of POST /mcp, as a value rather than an if-chain in a route.
 *
 * Extracted because the ORDER is the contract and it is easy to change by
 * accident. Two of these outcomes look interchangeable and are not:
 *
 *   404  a session id we do not hold. The client MUST start a new session
 *        (Streamable HTTP, 2025-03-26), and this is the only status that tells
 *        it so. Every restart depends on it.
 *   400  no session id at all and not an initialize. There is nothing to
 *        recover from — the request is genuinely malformed.
 *
 * The case that decides the order is an initialize request that still carries a
 * stale session id, which is exactly what a reconnecting client sends. It must
 * reach 'create' rather than 'not-found', or a client trying to recover is told
 * "not found" for the very request that would have fixed it.
 */
export function routeForSessionRequest(input: {
  hasRuntime: boolean;
  sessionId?: string;
  isInitialize: boolean;
}): SessionRoute {
  if (input.hasRuntime) return 'use-existing';
  if (input.isInitialize) return 'create';
  if (input.sessionId) return 'not-found';
  return 'no-session';
}

/**
 * SessionManager owns MCP session lifecycle, entirely in this process.
 *
 * There is no second store. See the note at the top of this file for why a
 * session is the one thing here that could not become a value, and what a
 * restart therefore costs.
 */
export class SessionManager {
  // Every session this process holds. The only session store there is.
  private runtimeSessions = new Map<string, RuntimeSession>();

  // Periodic reaper for sessions nobody is using any more. No longer optional:
  // when Redis held the records, its TTL expired them and this only dropped the
  // instances left behind. Now this timer IS session expiry, so a server that
  // does not start it leaks every session it ever creates.
  private sweepTimer?: NodeJS.Timeout;

  /**
   * Create a new session.
   *
   * Still connect-first: the transport connection is established before the
   * session is recorded, so a failed connect leaves nothing behind. That was
   * written to avoid orphaned Redis records and it earns its keep unchanged —
   * an entry in the map with a dead transport is the same bug without the round
   * trip.
   */
  async createSession(
    sessionId: string,
    sessionData: Omit<SessionData, 'createdAt' | 'lastAccessedAt'>,
    transport: StreamableHTTPServerTransport
  ): Promise<McpServer> {
    const now = Date.now();

    // Create MCP server and register tools first
    const server = new McpServer({
      name: 'insforge-mcp',
      version: PACKAGE_VERSION,
    });

    const toolsConfig = await registerInsforgeTools(sdkToolHost(server), {
      apiKey: sessionData.apiKey,
      apiBaseUrl: sessionData.apiBaseUrl,
      mode: 'remote',
      projectId: sessionData.projectId,
      accessToken: sessionData.oauthTokenHash,
    });

    // Connect the server to the transport before recording the session, so a
    // failed connect leaves nothing behind.
    await server.connect(transport);

    const fullSessionData: SessionData = {
      ...sessionData,
      createdAt: now,
      lastAccessedAt: now,
      backendVersion: toolsConfig.backendVersion,
    };

    this.runtimeSessions.set(sessionId, {
      server,
      transport,
      transportType: 'streamable',
      data: fullSessionData,
      lastSeenAt: monotonicNow(),
      openStreams: 0,
    });

    console.log(`[SessionManager] Session created: ${sessionFingerprint(sessionId)}`);
    return server;
  }

  /**
   * The data half of a session, or null.
   *
   * Synchronous now, and that is the whole shape of this change: it used to be
   * a network round trip on the path of every request that carried a session
   * id.
   */
  getSessionData(sessionId: string): SessionData | null {
    return this.runtimeSessions.get(sessionId)?.data ?? null;
  }

  /**
   * Get runtime session (transport + server) from memory
   */
  getRuntimeSession(sessionId: string): RuntimeSession | null {
    return this.runtimeSessions.get(sessionId) || null;
  }

  /**
   * Get runtime session with Streamable HTTP transport
   * Returns null if session doesn't exist or uses SSE transport
   */
  getStreamableSession(sessionId: string): { server: McpServer; transport: StreamableHTTPServerTransport } | null {
    const session = this.runtimeSessions.get(sessionId);
    if (!session || session.transportType !== 'streamable') {
      return null;
    }
    return { server: session.server, transport: session.transport as StreamableHTTPServerTransport };
  }

  /**
   * Get runtime session with SSE transport
   * Returns null if session doesn't exist or uses Streamable HTTP transport
   */
  getSSESession(sessionId: string): { server: McpServer; transport: SSEServerTransport } | null {
    const session = this.runtimeSessions.get(sessionId);
    if (!session || session.transportType !== 'sse') {
      return null;
    }
    return { server: session.server, transport: session.transport as SSEServerTransport };
  }

  /**
   * Does this process hold this session?
   *
   * There is no longer any other place it could be, which is why
   * `restoreSession` is gone rather than shrunk. It rebuilt a server and
   * transport from a Redis record around a reused session id; with no record,
   * the honest answer to an unknown id is 404 and the client initializes again.
   * A method that could only ever return null would just move that decision
   * somewhere less visible.
   */
  hasSession(sessionId: string): boolean {
    return this.runtimeSessions.has(sessionId);
  }

  /**
   * Create a new SSE session (for legacy SSE transport).
   *
   * Connect-first, same as the streamable path and for the same reason.
   */
  async createSSESession(
    sessionId: string,
    sessionData: Omit<SessionData, 'createdAt' | 'lastAccessedAt'>,
    transport: SSEServerTransport
  ): Promise<McpServer> {
    const now = Date.now();

    // Create MCP server and register tools first
    const server = new McpServer({
      name: 'insforge-mcp',
      version: PACKAGE_VERSION,
    });

    const toolsConfig = await registerInsforgeTools(sdkToolHost(server), {
      apiKey: sessionData.apiKey,
      apiBaseUrl: sessionData.apiBaseUrl,
      mode: 'remote',
      projectId: sessionData.projectId,
      accessToken: sessionData.oauthTokenHash,
    });

    // Note: Type assertion needed due to SDK type compatibility issue
    await server.connect(transport as unknown as Parameters<typeof server.connect>[0]);

    const fullSessionData: SessionData = {
      ...sessionData,
      createdAt: now,
      lastAccessedAt: now,
      backendVersion: toolsConfig.backendVersion,
    };

    this.runtimeSessions.set(sessionId, {
      server,
      transport,
      transportType: 'sse',
      data: fullSessionData,
      lastSeenAt: monotonicNow(),
      openStreams: 0,
    });

    console.log(`[SessionManager] SSE session created: ${sessionFingerprint(sessionId)}`);
    return server;
  }

  /**
   * Update last accessed time and refresh TTL
   */
  /**
   * Register a server->client stream as open, and stamp the session.
   *
   * Deliberately a count rather than a flag: a client may reconnect its stream
   * before the old response has finished closing, and a flag cleared by the
   * departing one would leave a live stream unprotected.
   */
  openStream(sessionId: string): void {
    const runtime = this.runtimeSessions.get(sessionId);
    if (!runtime) return;
    runtime.openStreams += 1;
    runtime.lastSeenAt = monotonicNow();
  }

  /**
   * Release a stream. Safe to call for a session that has already been deleted,
   * which happens whenever a close event lands after a reap or a DELETE.
   */
  closeStream(sessionId: string): void {
    const runtime = this.runtimeSessions.get(sessionId);
    if (!runtime) return;
    runtime.openStreams = Math.max(0, runtime.openStreams - 1);
    // The stream was alive right up to this moment; start the idle clock here
    // rather than from whenever it opened.
    runtime.lastSeenAt = monotonicNow();
  }

  /** Open stream count, for tests and diagnostics. */
  getOpenStreamCount(sessionId: string): number {
    return this.runtimeSessions.get(sessionId)?.openStreams ?? 0;
  }

  /**
   * Record that we just heard from this client.
   *
   * Two clocks, deliberately, and they are not redundant. `lastSeenAt` is
   * monotonic and drives expiry — see monotonicNow() for why wall-clock time
   * would let an NTP step age every session out at once. `lastAccessedAt` is
   * wall-clock and is only ever read by a human or a diagnostic, where a
   * monotonic number would be meaningless.
   */
  touchSession(sessionId: string): void {
    const runtime = this.runtimeSessions.get(sessionId);
    if (!runtime) return;

    runtime.lastSeenAt = monotonicNow();
    runtime.data.lastAccessedAt = Date.now();
  }

  /**
   * Close a session and forget it.
   */
  async deleteSession(sessionId: string): Promise<void> {
    const runtime = this.runtimeSessions.get(sessionId);
    if (!runtime) {
      return;
    }

    try {
      await runtime.server.close();
      await runtime.transport.close();
    } catch (error) {
      console.error(`[SessionManager] Error closing session ${sessionFingerprint(sessionId)}:`, error);
    }
    // Outside the try: a close that throws must still drop the entry, or a
    // session that failed to shut down cleanly is held for the life of the
    // process and never swept — the sweep only reaps what it can close.
    this.runtimeSessions.delete(sessionId);

    console.log(`[SessionManager] Session deleted: ${sessionFingerprint(sessionId)}`);
  }

  /**
   * Drop sessions nobody is using any more, closing each one.
   * Returns how many were reaped.
   */
  async sweepOrphanedSessions(): Promise<number> {
    // Streamable HTTP only. SSE has a real disconnect signal and cleans itself
    // up on res 'close' — that asymmetry is the whole reason this reaper exists.
    // Sweeping SSE too would close live connections: nothing on the SSE message
    // path stamps lastSeenAt, so an SSE session reads as idle from the moment it
    // is created whether or not the client is active, and the keepalive means
    // such a connection is still open when it does.
    const candidates: SweepCandidate[] = Array.from(this.runtimeSessions.entries())
      .filter(([, session]) => session.transportType === 'streamable')
      .map(([sessionId, session]) => ({
        sessionId,
        lastSeenAt: session.lastSeenAt,
        openStreams: session.openStreams,
      }));
    if (candidates.length === 0) {
      return 0;
    }

    const selected = selectOrphanedSessions(candidates);

    // Re-check each one against the live entry immediately before closing it.
    //
    // This mattered more when a Redis round trip sat between the snapshot and
    // the decision, and it is KEPT rather than removed with the round trip: the
    // loop below awaits deleteSession for each id, so a request can still land
    // between the snapshot and this session's turn. Acting on the snapshot
    // would close a session that has just proved it is alive.
    const orphaned: string[] = [];
    for (const sessionId of selected) {
      const current = this.runtimeSessions.get(sessionId);
      if (!current) continue;
      if (current.openStreams > 0 || monotonicNow() - current.lastSeenAt < SESSION_TTL_MS) {
        continue;
      }
      await this.deleteSession(sessionId);
      orphaned.push(sessionId);
    }

    if (orphaned.length > 0) {
      console.log(
        `[SessionManager] Swept ${orphaned.length} orphaned session(s); ${this.runtimeSessions.size} remain in memory`
      );
    }
    return orphaned.length;
  }

  /**
   * Start the periodic sweep. Idempotent; the timer is unref'd so it never
   * holds the process open on shutdown.
   *
   * This is now the ONLY thing that expires a session. It used to be gated on
   * Redis being configured, which was correct then — Redis owned the lifetime
   * and this only reclaimed the instances left behind — and would be a memory
   * leak now. The gate is gone from the caller for exactly that reason.
   */
  startIdleSweep(intervalMs: number = SESSION_SWEEP_MS): void {
    if (this.sweepTimer) {
      return;
    }
    this.sweepTimer = setInterval(() => {
      this.sweepOrphanedSessions().catch((error) => {
        console.error('[SessionManager] Sweep failed:', error);
      });
    }, intervalMs);
    this.sweepTimer.unref();
  }

  /**
   * Stop the periodic sweep.
   */
  stopIdleSweep(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = undefined;
    }
  }

  /**
   * Get all session IDs (from memory - for graceful shutdown)
   */
  getActiveSessionIds(): string[] {
    return Array.from(this.runtimeSessions.keys());
  }

  /**
   * Close all sessions (for graceful shutdown)
   */
  async closeAllSessions(): Promise<void> {
    const sessionIds = this.getActiveSessionIds();
    console.log(`[SessionManager] Closing ${sessionIds.length} sessions...`);

    for (const sessionId of sessionIds) {
      await this.deleteSession(sessionId);
    }

    console.log('[SessionManager] All sessions closed');
  }

  /**
   * Session statistics for /health.
   *
   * Both numbers are kept, and they are now necessarily equal — there is one
   * store, so there is nothing for them to disagree about. The pair used to
   * mean something: `activeSessions` counted Redis records and
   * `memorySessionCount` counted resident instances, and a ratio far from 1 was
   * the signal that instances were piling up behind expired records. That is
   * the leak the sweep exists to prevent, and it can no longer be detected this
   * way.
   *
   * They stay because /health is a published shape that a monitor reads, and
   * silently dropping a field breaks the reader rather than telling it. What
   * replaces the ratio as a leak signal is `memorySessionCount` against heap —
   * measured at roughly 252 kB per session against this machine's ~493 MB heap
   * limit, so about 2,000 resident sessions is where the process dies. That
   * number belongs in whatever ends up watching this endpoint.
   */
  getStats(): {
    activeSessions: number;
    memorySessionCount: number;
  } {
    return {
      activeSessions: this.runtimeSessions.size,
      memorySessionCount: this.runtimeSessions.size,
    };
  }
}

// Singleton instance
let sessionManager: SessionManager | null = null;

/**
 * Get or create the singleton SessionManager
 */
export function getSessionManager(): SessionManager {
  if (!sessionManager) {
    sessionManager = new SessionManager();
  }
  return sessionManager;
}
