import { describe, it, expect } from 'vitest';
import { resolveRedisClientSpec, isRedisConfigured, type RedisConfig } from './redis.js';

/**
 * These exist because of a bug that was invisible: REDIS_PASSWORD was read into
 * a config object nothing imported, while the real client built its own options
 * and never sent a password. Every managed Redis requires AUTH, so the server
 * could not connect to one — and the env var sat there looking correct.
 *
 * The assertions are on the resolved spec rather than a live client, so they
 * check what ioredis is actually handed without opening a socket.
 */

const base: RedisConfig = {
  host: 'redis.internal',
  port: 6379,
  tls: false,
  cluster: false,
};

describe('resolveRedisClientSpec — standalone', () => {
  it('passes the password through to ioredis', () => {
    const spec = resolveRedisClientSpec({ ...base, password: 's3cret' });
    expect(spec.kind).toBe('standalone');
    expect(spec.options.password).toBe('s3cret');
  });

  it('passes a username through for ACL-style auth', () => {
    const spec = resolveRedisClientSpec({ ...base, username: 'app', password: 's3cret' });
    expect(spec.options.username).toBe('app');
    expect(spec.options.password).toBe('s3cret');
  });

  it('omits credentials entirely when none are configured', () => {
    const spec = resolveRedisClientSpec(base);
    expect(spec.options).not.toHaveProperty('password');
    expect(spec.options).not.toHaveProperty('username');
  });

  it('keeps host, port and the retry policy', () => {
    const spec = resolveRedisClientSpec(base);
    expect(spec.options.host).toBe('redis.internal');
    expect(spec.options.port).toBe(6379);
    expect(spec.options.maxRetriesPerRequest).toBe(3);
  });

  it('enables TLS when asked', () => {
    expect(resolveRedisClientSpec({ ...base, tls: true }).options.tls).toEqual({});
    expect(resolveRedisClientSpec(base).options).not.toHaveProperty('tls');
  });
});

describe('resolveRedisClientSpec — URL', () => {
  // The shape managed Redis is normally handed over in: one variable with the
  // credentials already embedded.
  it('is used verbatim so ioredis can parse credentials out of it', () => {
    const spec = resolveRedisClientSpec({
      ...base,
      url: 'redis://app:s3cret@redis.example:6380',
    });
    expect(spec).toMatchObject({ kind: 'url', url: 'redis://app:s3cret@redis.example:6380' });
  });

  it('carries the retry policy alongside the URL', () => {
    const spec = resolveRedisClientSpec({ ...base, url: 'rediss://redis.example:6380' });
    expect(spec.options.maxRetriesPerRequest).toBe(3);
  });

  it('takes precedence over the discrete host and port', () => {
    const spec = resolveRedisClientSpec({
      ...base,
      host: 'ignored.example',
      url: 'redis://redis.example:6380',
    });
    expect(spec.kind).toBe('url');
    expect(spec.options).not.toHaveProperty('host');
  });

  it('does not hijack cluster mode', () => {
    // Cluster is configured by node list, not by URL — a URL alongside it must
    // not silently downgrade the client to standalone.
    const spec = resolveRedisClientSpec({ ...base, cluster: true, url: 'redis://x:6379' });
    expect(spec.kind).toBe('cluster');
  });
});

describe('resolveRedisClientSpec — cluster', () => {
  it('sends credentials via redisOptions, where the cluster client reads them', () => {
    const spec = resolveRedisClientSpec({
      ...base,
      cluster: true,
      username: 'app',
      password: 's3cret',
    });
    expect(spec.kind).toBe('cluster');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const redisOptions = (spec.options as any).redisOptions;
    expect(redisOptions.password).toBe('s3cret');
    expect(redisOptions.username).toBe('app');
  });

  it('still targets the configured node and enables TLS', () => {
    const spec = resolveRedisClientSpec({ ...base, cluster: true, tls: true });
    expect(spec).toMatchObject({ nodes: [{ host: 'redis.internal', port: 6379 }] });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((spec.options as any).redisOptions.tls).toEqual({});
  });
});

describe('isRedisConfigured', () => {
  // The boot ping used to be unconditional, so a container with no Redis
  // exited 1 before app.listen and nothing was reachable — not /health, not
  // discovery, not a log line naming the cause. This predicate is what lets
  // the server come up and say so instead.
  it('is true when a URL or a host is given', () => {
    expect(isRedisConfigured({ REDIS_URL: 'redis://cache:6379' })).toBe(true);
    expect(isRedisConfigured({ REDIS_HOST: 'cache' })).toBe(true);
  });

  it('is false when nothing points anywhere', () => {
    expect(isRedisConfigured({})).toBe(false);
    expect(isRedisConfigured({ REDIS_URL: '', REDIS_HOST: '' })).toBe(false);
  });

  it('does not count a port, a password or TLS as a destination', () => {
    // getRedisConfig defaults the host to localhost, so counting any of these
    // would mean "configured" and send us straight back to a connection that
    // can never succeed — the failure this exists to prevent.
    expect(isRedisConfigured({ REDIS_PORT: '6379' })).toBe(false);
    expect(isRedisConfigured({ REDIS_PASSWORD: 'hunter2' })).toBe(false);
    expect(isRedisConfigured({ REDIS_TLS: 'true', REDIS_CLUSTER: 'true' })).toBe(false);
  });
});
