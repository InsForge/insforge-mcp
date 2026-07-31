import Redis, { Cluster, type RedisOptions } from 'ioredis';

export interface RedisConfig {
  /**
   * Full connection URL, e.g. redis://user:pass@host:6379 or rediss://…
   * Managed Redis is usually handed over this way with credentials embedded,
   * so when it's set it wins over the discrete fields.
   */
  url?: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  tls: boolean;
  cluster: boolean;
}

/**
 * How the client will be built, kept as data so it can be asserted without
 * opening a socket. The bug this replaced was a password that looked
 * configured and never reached ioredis, which no test could have caught while
 * the options were built inline.
 */
export type RedisClientSpec =
  | { kind: 'url'; url: string; options: RedisOptions }
  | { kind: 'standalone'; options: RedisOptions }
  | { kind: 'cluster'; nodes: Array<{ host: string; port: number }>; options: RedisOptions };

const BASE_OPTIONS: RedisOptions = {
  maxRetriesPerRequest: 3,
  retryStrategy(times: number) {
    return Math.min(times * 100, 3000);
  },
};

/**
 * Get Redis configuration from environment variables
 */
export function getRedisConfig(): RedisConfig {
  return {
    url: process.env.REDIS_URL || undefined,
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    username: process.env.REDIS_USERNAME || undefined,
    password: process.env.REDIS_PASSWORD || undefined,
    tls: process.env.REDIS_TLS === 'true',
    cluster: process.env.REDIS_CLUSTER === 'true',
  };
}

/**
 * Has anyone actually pointed us at a Redis?
 *
 * `getRedisConfig` defaults the host to localhost, which is a sensible default
 * for a developer and a lie in a container — nothing is listening there, so the
 * server retried a connection that could never succeed and exited 1 before
 * `app.listen`. That is what 19 Manufact deploys failed on after the missing
 * start script was fixed.
 *
 * REDIS_PORT is deliberately not counted: a port with no host is not a
 * destination, and treating it as one would put us straight back to localhost.
 */
export function isRedisConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return !!(env.REDIS_URL || env.REDIS_HOST);
}

/**
 * Resolve a config into the exact shape ioredis is constructed with.
 */
export function resolveRedisClientSpec(config: RedisConfig): RedisClientSpec {
  const { url, host, port, username, password, tls, cluster } = config;

  const credentials: RedisOptions = {
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
  };
  // A rediss:// URL already implies TLS; only the discrete flag needs translating.
  const tlsOptions: RedisOptions = tls ? { tls: {} } : {};

  if (cluster) {
    // Cluster mode (AWS ElastiCache Serverless, etc.)
    return {
      kind: 'cluster',
      nodes: [{ host, port }],
      options: {
        redisOptions: { ...credentials, ...tlsOptions },
        dnsLookup: (address: string, callback: (err: null, addr: string) => void) =>
          callback(null, address),
        slotsRefreshTimeout: 2000,
        enableReadyCheck: true,
      } as RedisOptions,
    };
  }

  if (url) {
    // ioredis parses username, password, host, port and the rediss:// TLS
    // switch straight out of the URL.
    return { kind: 'url', url, options: { ...BASE_OPTIONS } };
  }

  return {
    kind: 'standalone',
    options: { host, port, ...credentials, ...tlsOptions, ...BASE_OPTIONS },
  };
}

/**
 * Create a Redis client based on configuration
 * Supports a connection URL, standalone and cluster mode, with optional TLS.
 */
export function createRedisClient(config?: RedisConfig): Redis | Cluster {
  const spec = resolveRedisClientSpec(config || getRedisConfig());

  switch (spec.kind) {
    case 'cluster':
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return new Redis.Cluster(spec.nodes, spec.options as any);
    case 'url':
      return new Redis(spec.url, spec.options);
    default:
      return new Redis(spec.options);
  }
}

// Singleton instance
let redisClient: Redis | Cluster | null = null;

/**
 * Get or create the singleton Redis client
 */
export function getRedisClient(): Redis | Cluster {
  if (!redisClient) {
    redisClient = createRedisClient();

    redisClient.on('error', (err) => {
      console.error('[Redis] Connection error:', err.message);
    });

    redisClient.on('connect', () => {
      console.log('[Redis] Connected successfully');
    });

    redisClient.on('ready', () => {
      console.log('[Redis] Ready to accept commands');
    });
  }
  return redisClient;
}

/**
 * Close the Redis connection gracefully
 */
export async function closeRedisClient(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
    console.log('[Redis] Connection closed');
  }
}
