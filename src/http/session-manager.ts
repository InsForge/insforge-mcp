import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { getRedisClient } from './redis.js';
import { SESSION_SWEEP_MS } from './config.js';
import { registerInsforgeTools } from '../shared/tools/index.js';
import { PACKAGE_VERSION } from '../shared/version.js';

/**
 * Session data stored in Redis
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
 * In-memory runtime instances (cannot be serialized to Redis)
 */
interface RuntimeSession {
  server: McpServer;
  transport: StreamableHTTPServerTransport | SSEServerTransport;
  transportType: 'streamable' | 'sse';
  // Last time this process saw real client traffic for the session, on the
  // monotonic clock. Tracked in memory because it is the only record of
  // activity that survives Redis losing its data — see selectOrphanedSessions.
  lastSeenAt: number;
}

// Redis key prefix
const SESSION_KEY_PREFIX = 'mcp:session:';

// Session TTL in seconds (24 hours)
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
}

/**
 * Pick the runtime sessions that no longer have a Redis record.
 *
 * Redis owns session lifetime — the record expires on SESSION_TTL — but the
 * in-memory McpServer and transport are only dropped on an explicit DELETE.
 * Streamable HTTP clients mostly never send one, so anything whose record has
 * gone is an orphan holding a server, a transport and a full tool registry.
 *
 * `exists` is the pipelined EXISTS reply for the matching id. A missing or
 * failed reply counts as alive: a transient Redis error must never be read as
 * "reap this live session".
 *
 * A missing record is necessary but not sufficient. Redis can also come back
 * empty — a restart without persistence, a failover to a cold replica, an
 * eviction — and then every resident session reads as an orphan at once, so
 * the sweep would close connections that are actively serving traffic.
 * touchSession cannot repair that: it only rewrites a record it can still
 * read, so a wiped record stays wiped no matter how busy the client is.
 *
 * The in-memory clock settles it. A record only expires SESSION_TTL after the
 * last touch, and that same touch stamps lastSeenAt, so the two cross at the
 * same instant during normal operation and this gate costs no reap latency.
 * They diverge in exactly one case: Redis lost a record early. Then the
 * session we saw traffic on minutes ago is held, and one genuinely abandoned
 * is still collected on schedule.
 */
export function selectOrphanedSessions(
  sessions: SweepCandidate[],
  exists: number[],
  now: number = monotonicNow()
): string[] {
  return sessions
    .filter((session, i) => exists[i] === 0 && now - session.lastSeenAt >= SESSION_TTL_MS)
    .map((session) => session.sessionId);
}

/**
 * SessionManager handles MCP session lifecycle with Redis persistence
 *
 * Storage strategy:
 * - Redis: SessionData (persistent, shareable across instances)
 * - Memory: McpServer + Transport instances (runtime only)
 */
export class SessionManager {
  // In-memory cache for runtime instances
  private runtimeSessions = new Map<string, RuntimeSession>();

  // Periodic reaper for runtime sessions Redis has already expired
  private sweepTimer?: NodeJS.Timeout;

  /**
   * Create a new session
   *
   * Uses connect-first strategy: establishes transport connection before
   * persisting to Redis to avoid orphaned records if connection fails
   */
  async createSession(
    sessionId: string,
    sessionData: Omit<SessionData, 'createdAt' | 'lastAccessedAt'>,
    transport: StreamableHTTPServerTransport
  ): Promise<McpServer> {
    const redis = getRedisClient();
    const now = Date.now();

    // Create MCP server and register tools first
    const server = new McpServer({
      name: 'insforge-mcp',
      version: PACKAGE_VERSION,
    });

    const toolsConfig = await registerInsforgeTools(server, {
      apiKey: sessionData.apiKey,
      apiBaseUrl: sessionData.apiBaseUrl,
      mode: 'remote',
      projectId: sessionData.projectId,
      accessToken: sessionData.oauthTokenHash,
    });

    // Connect server to transport BEFORE persisting to Redis
    // This ensures we don't create orphaned Redis records if connection fails
    await server.connect(transport);

    // Only persist after successful connection
    const fullSessionData: SessionData = {
      ...sessionData,
      createdAt: now,
      lastAccessedAt: now,
      backendVersion: toolsConfig.backendVersion,
    };

    // Store in Redis with TTL
    await redis.setex(
      SESSION_KEY_PREFIX + sessionId,
      SESSION_TTL,
      JSON.stringify(fullSessionData)
    );

    // Store runtime instances in memory
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'streamable', lastSeenAt: monotonicNow() });

    console.log(`[SessionManager] Session created: ${sessionId}`);
    return server;
  }

  /**
   * Get session data from Redis
   */
  async getSessionData(sessionId: string): Promise<SessionData | null> {
    const redis = getRedisClient();
    const data = await redis.get(SESSION_KEY_PREFIX + sessionId);

    if (!data) {
      return null;
    }

    return JSON.parse(data) as SessionData;
  }

  /**
   * Get runtime session (transport + server) from memory
   * If session exists in Redis but not in memory, it needs to be restored
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
   * Check if session exists (either in memory or Redis)
   */
  async hasSession(sessionId: string): Promise<boolean> {
    // Check memory first (fast path)
    if (this.runtimeSessions.has(sessionId)) {
      return true;
    }

    // Check Redis
    const redis = getRedisClient();
    const exists = await redis.exists(SESSION_KEY_PREFIX + sessionId);
    return exists === 1;
  }

  /**
   * Restore a session from Redis into memory
   * Called when request comes in with session ID but runtime is not in memory
   * (e.g., after server restart or load balancer routing to different instance)
   */
  async restoreSession(
    sessionId: string,
    transport: StreamableHTTPServerTransport
  ): Promise<McpServer | null> {
    const sessionData = await this.getSessionData(sessionId);

    if (!sessionData) {
      console.log(`[SessionManager] Session not found in Redis: ${sessionId}`);
      return null;
    }

    console.log(`[SessionManager] Restoring session from Redis: ${sessionId}`);

    // Create new MCP server with stored configuration
    const server = new McpServer({
      name: 'insforge-mcp',
      version: PACKAGE_VERSION,
    });

    await registerInsforgeTools(server, {
      apiKey: sessionData.apiKey,
      apiBaseUrl: sessionData.apiBaseUrl,
      mode: 'remote',
      projectId: sessionData.projectId,
      accessToken: sessionData.oauthTokenHash,
    });

    await server.connect(transport);

    // Store runtime instances in memory
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'streamable', lastSeenAt: monotonicNow() });

    // Update last accessed time
    await this.touchSession(sessionId);

    console.log(`[SessionManager] Session restored: ${sessionId}`);
    return server;
  }

  /**
   * Create a new SSE session (for legacy SSE transport)
   *
   * Uses connect-first strategy: establishes transport connection before
   * persisting to Redis to avoid orphaned records if connection fails
   */
  async createSSESession(
    sessionId: string,
    sessionData: Omit<SessionData, 'createdAt' | 'lastAccessedAt'>,
    transport: SSEServerTransport
  ): Promise<McpServer> {
    const redis = getRedisClient();
    const now = Date.now();

    // Create MCP server and register tools first
    const server = new McpServer({
      name: 'insforge-mcp',
      version: PACKAGE_VERSION,
    });

    const toolsConfig = await registerInsforgeTools(server, {
      apiKey: sessionData.apiKey,
      apiBaseUrl: sessionData.apiBaseUrl,
      mode: 'remote',
      projectId: sessionData.projectId,
      accessToken: sessionData.oauthTokenHash,
    });

    // Connect server to SSE transport BEFORE persisting to Redis
    // This ensures we don't create orphaned Redis records if connection fails
    // Note: Type assertion needed due to SDK type compatibility issue
    await server.connect(transport as unknown as Parameters<typeof server.connect>[0]);

    // Only persist after successful connection
    const fullSessionData: SessionData = {
      ...sessionData,
      createdAt: now,
      lastAccessedAt: now,
      backendVersion: toolsConfig.backendVersion,
    };

    // Store in Redis with TTL
    await redis.setex(
      SESSION_KEY_PREFIX + sessionId,
      SESSION_TTL,
      JSON.stringify(fullSessionData)
    );

    // Store runtime instances in memory
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'sse', lastSeenAt: monotonicNow() });

    console.log(`[SessionManager] SSE session created: ${sessionId}`);
    return server;
  }

  /**
   * Update last accessed time and refresh TTL
   */
  async touchSession(sessionId: string): Promise<void> {
    const redis = getRedisClient();

    // Stamp memory first and unconditionally. The Redis write below is a
    // no-op when the record is already gone, so this is the only evidence of
    // activity that outlives Redis losing its data.
    const runtime = this.runtimeSessions.get(sessionId);
    if (runtime) {
      runtime.lastSeenAt = monotonicNow();
    }

    const sessionData = await this.getSessionData(sessionId);

    if (sessionData) {
      sessionData.lastAccessedAt = Date.now();
      await redis.setex(
        SESSION_KEY_PREFIX + sessionId,
        SESSION_TTL,
        JSON.stringify(sessionData)
      );
    }
  }

  /**
   * Delete a session from both Redis and memory
   */
  async deleteSession(sessionId: string): Promise<void> {
    const redis = getRedisClient();

    // Close runtime instances
    const runtime = this.runtimeSessions.get(sessionId);
    if (runtime) {
      try {
        await runtime.server.close();
        await runtime.transport.close();
      } catch (error) {
        console.error(`[SessionManager] Error closing session ${sessionId}:`, error);
      }
      this.runtimeSessions.delete(sessionId);
    }

    // Delete from Redis
    await redis.del(SESSION_KEY_PREFIX + sessionId);

    console.log(`[SessionManager] Session deleted: ${sessionId}`);
  }

  /**
   * Drop runtime sessions whose Redis record has gone, closing each one.
   * Returns how many were reaped.
   */
  async sweepOrphanedSessions(): Promise<number> {
    // Streamable HTTP only. SSE has a real disconnect signal and cleans itself
    // up on res 'close' — that asymmetry is the whole reason this reaper exists.
    // Sweeping SSE too would close live connections: nothing on the SSE message
    // path refreshes the record, so it lapses at SESSION_TTL from creation
    // whether or not the client is active, and the keepalive means such a
    // connection is still open when it does.
    const candidates: SweepCandidate[] = Array.from(this.runtimeSessions.entries())
      .filter(([, session]) => session.transportType === 'streamable')
      .map(([sessionId, session]) => ({ sessionId, lastSeenAt: session.lastSeenAt }));
    if (candidates.length === 0) {
      return 0;
    }

    const redis = getRedisClient();
    const pipeline = redis.pipeline();
    for (const { sessionId } of candidates) {
      pipeline.exists(SESSION_KEY_PREFIX + sessionId);
    }
    const replies = await pipeline.exec();

    // A failed or absent reply is treated as "still alive" so a Redis blip
    // can't take out live sessions.
    const exists = candidates.map((_, i) => {
      const reply = replies?.[i];
      if (!reply || reply[0]) return 1;
      return Number(reply[1]);
    });

    const orphaned = selectOrphanedSessions(candidates, exists);
    for (const sessionId of orphaned) {
      await this.deleteSession(sessionId);
    }

    // Records gone while the session is still inside its TTL means Redis lost
    // data rather than expired it. Worth a line in the log: these sessions
    // survive the sweep but their records will not come back on their own.
    const heldBack = exists.filter((e) => e === 0).length - orphaned.length;
    if (heldBack > 0) {
      console.warn(
        `[SessionManager] ${heldBack} session(s) lost their Redis record before TTL — holding them; check Redis for a restart, failover or eviction`
      );
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
   * Get session statistics
   */
  async getStats(): Promise<{
    activeSessions: number;
    memorySessionCount: number;
  }> {
    const redis = getRedisClient();

    // Count sessions in Redis (using SCAN to avoid blocking)
    let cursor = '0';
    let count = 0;

    do {
      const [newCursor, keys] = await redis.scan(
        cursor,
        'MATCH',
        SESSION_KEY_PREFIX + '*',
        'COUNT',
        100
      );
      cursor = newCursor;
      count += keys.length;
    } while (cursor !== '0');

    return {
      activeSessions: count,
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
