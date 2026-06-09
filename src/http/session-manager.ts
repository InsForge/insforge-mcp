import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { getRedisClient } from './redis.js';
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
}

// Redis key prefix
const SESSION_KEY_PREFIX = 'mcp:session:';

// Session TTL in seconds (24 hours)
const SESSION_TTL = 24 * 60 * 60;

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
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'streamable' });

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
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'streamable' });

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
    this.runtimeSessions.set(sessionId, { server, transport, transportType: 'sse' });

    console.log(`[SessionManager] SSE session created: ${sessionId}`);
    return server;
  }

  /**
   * Update last accessed time and refresh TTL
   */
  async touchSession(sessionId: string): Promise<void> {
    const redis = getRedisClient();
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
