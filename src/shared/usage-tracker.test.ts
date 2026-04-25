import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseAppKey, UsageTracker } from './usage-tracker.js';

// Mock node-fetch — vi.mock is hoisted, so use vi.hoisted for the mock fn
const { mockFetch } = vi.hoisted(() => ({ mockFetch: vi.fn() }));
vi.mock('node-fetch', () => ({ default: mockFetch }));

describe('parseAppKey', () => {
  it('should parse app-key from valid insforge.app URL', () => {
    expect(parseAppKey('https://uhzx8md3.us-test.insforge.app')).toBe('uhzx8md3');
  });

  it('should parse app-key from different regions', () => {
    expect(parseAppKey('https://4cp6qchj.us-east.insforge.app')).toBe('4cp6qchj');
  });

  it('should return null for non-insforge.app domain', () => {
    expect(parseAppKey('https://4cp6ast.insforge.dev')).toBeNull();
  });

  it('should return null for localhost', () => {
    expect(parseAppKey('http://localhost:7130')).toBeNull();
  });

  it('should return null for invalid URL', () => {
    expect(parseAppKey('not-a-url')).toBeNull();
  });

  it('should return null for insforge.app without region segment', () => {
    expect(parseAppKey('https://myapp.insforge.app')).toBeNull();
  });

  it('should return null for too many subdomains', () => {
    // hostname: a.b.c.insforge.app — the regex expects exactly {key}.{region}.insforge.app
    expect(parseAppKey('https://a.b.c.insforge.app')).toBeNull();
  });
});

describe('UsageTracker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({ ok: true });
  });

  it('should not track usage when apiKey is empty', async () => {
    const tracker = new UsageTracker('http://localhost:7130', '');
    await tracker.trackUsage('test-tool');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('should send usage tracking request', async () => {
    const tracker = new UsageTracker('https://myapp.us-east.insforge.app', 'test-key');
    await tracker.trackUsage('fetch-docs', true);

    // Should have called fetch twice: agent-connected + usage tracking
    expect(mockFetch).toHaveBeenCalledTimes(2);

    // Usage tracking call
    const usageCall = mockFetch.mock.calls.find(
      (call: string[]) => call[0].includes('/api/usage/mcp')
    );
    expect(usageCall).toBeDefined();
    const usageBody = JSON.parse(usageCall![1].body);
    expect(usageBody.tool_name).toBe('fetch-docs');
    expect(usageBody.success).toBe(true);
  });

  describe('agent-connected reporting', () => {
    it('should report agent-connected with app_key in local mode', async () => {
      const tracker = new UsageTracker(
        'https://uhzx8md3.us-test.insforge.app',
        'test-key',
        { isRemote: false }
      );
      await tracker.trackUsage('fetch-docs');

      const agentCall = mockFetch.mock.calls.find(
        (call: string[]) => call[0].includes('/tracking/v1/agent-connected')
      );
      expect(agentCall).toBeDefined();
      expect(agentCall![0]).toBe('https://api.insforge.dev/tracking/v1/agent-connected');

      const body = JSON.parse(agentCall![1].body);
      expect(body.app_key).toBe('uhzx8md3');
      expect(body.project_id).toBeUndefined();
      expect(body.client).toBe('mcp');

      // No Authorization header in local mode
      expect(agentCall![1].headers['Authorization']).toBeUndefined();
    });

    it('should report agent-connected with project_id in remote mode', async () => {
      const tracker = new UsageTracker(
        'https://myapp.us-east.insforge.app',
        'test-key',
        { isRemote: true, projectId: '550e8400-e29b-41d4-a716-446655440000', accessToken: 'my-token' }
      );
      await tracker.trackUsage('fetch-docs');

      const agentCall = mockFetch.mock.calls.find(
        (call: string[]) => call[0].includes('/tracking/v1/agent-connected')
      );
      expect(agentCall).toBeDefined();

      const body = JSON.parse(agentCall![1].body);
      expect(body.project_id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(body.app_key).toBeUndefined();

      expect(agentCall![1].headers['Authorization']).toBe('Bearer my-token');
    });

    it('should fall back to app_key for legacy remote sessions', async () => {
      const tracker = new UsageTracker(
        'https://4cp6qchj.us-east.insforge.app',
        'test-key',
        { isRemote: true, projectId: 'legacy', accessToken: 'legacy' }
      );
      await tracker.trackUsage('fetch-docs');

      const agentCall = mockFetch.mock.calls.find(
        (call: string[]) => call[0].includes('/tracking/v1/agent-connected')
      );
      expect(agentCall).toBeDefined();

      const body = JSON.parse(agentCall![1].body);
      expect(body.app_key).toBe('4cp6qchj');
      expect(body.project_id).toBeUndefined();
    });

    it('should not report agent-connected if apiBaseUrl is not a valid insforge.app URL (local mode)', async () => {
      const tracker = new UsageTracker(
        'http://localhost:7130',
        'test-key',
        { isRemote: false }
      );
      await tracker.trackUsage('fetch-docs');

      const agentCall = mockFetch.mock.calls.find(
        (call: string[]) => call[0].includes('/tracking/v1/agent-connected')
      );
      expect(agentCall).toBeUndefined();
    });

    it('should only report agent-connected once across multiple trackUsage calls', async () => {
      const tracker = new UsageTracker(
        'https://uhzx8md3.us-test.insforge.app',
        'test-key',
        { isRemote: false }
      );

      await tracker.trackUsage('fetch-docs');
      await tracker.trackUsage('get-backend-metadata');
      await tracker.trackUsage('list-buckets');

      const agentCalls = mockFetch.mock.calls.filter(
        (call: string[]) => call[0].includes('/tracking/v1/agent-connected')
      );
      expect(agentCalls).toHaveLength(1);
    });

    it('should not block trackUsage if agent-connected fails', async () => {
      mockFetch.mockImplementation(async (url: string) => {
        if (url.includes('/tracking/v1/agent-connected')) {
          throw new Error('Network error');
        }
        return { ok: true };
      });

      const tracker = new UsageTracker(
        'https://uhzx8md3.us-test.insforge.app',
        'test-key',
        { isRemote: false }
      );

      // Should not throw
      await tracker.trackUsage('fetch-docs');

      // Usage tracking call should still happen
      const usageCall = mockFetch.mock.calls.find(
        (call: string[]) => call[0].includes('/api/usage/mcp')
      );
      expect(usageCall).toBeDefined();
    });
  });
});
