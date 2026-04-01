import fetch from 'node-fetch';

const PLATFORM_API_BASE = 'https://api.insforge.dev';

/**
 * Parse app-key from an Insforge API base URL.
 * Valid format: https://{app-key}.{region}.insforge.app
 * Returns the app-key or null if the URL doesn't match.
 */
export function parseAppKey(apiBaseUrl: string): string | null {
  try {
    const url = new URL(apiBaseUrl);
    const match = url.hostname.match(/^([^.]+)\.[^.]+\.insforge\.app$/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

export class UsageTracker {
  private apiBaseUrl: string;
  private apiKey: string;
  private agentConnectedReported = false;
  private projectId?: string;
  private accessToken?: string;
  private isRemote: boolean;

  constructor(
    apiBaseUrl: string,
    apiKey: string,
    options?: { projectId?: string; accessToken?: string; isRemote?: boolean }
  ) {
    this.apiBaseUrl = apiBaseUrl;
    this.apiKey = apiKey;
    this.projectId = options?.projectId;
    this.accessToken = options?.accessToken;
    this.isRemote = options?.isRemote ?? false;
  }

  async trackUsage(toolName: string, success: boolean = true): Promise<void> {
    if (!this.apiKey) {
      return;
    }

    // Report agent-connected once on first usage
    if (!this.agentConnectedReported) {
      this.agentConnectedReported = true;
      this.reportAgentConnected().catch((error) => {
        console.error('Failed to report agent-connected:', error);
      });
    }

    try {
      const payload = {
        tool_name: toolName,
        success,
        timestamp: new Date().toISOString(),
      };

      await fetch(`${this.apiBaseUrl}/api/usage/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
        },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      // Silently fail to not interrupt the main flow
      console.error('Failed to track usage:', error);
    }
  }

  private async reportAgentConnected(): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: Record<string, any> = {};
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const headers: Record<string, any> = { 'Content-Type': 'application/json' };

    if (this.isRemote && this.projectId && this.projectId !== 'legacy') {
      body.project_id = this.projectId;
      if (this.accessToken) {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
      }
    } else {
      const appKey = parseAppKey(this.apiBaseUrl);
      if (!appKey) {
        return;
      }
      body.app_key = appKey;
    }

    await fetch(`${PLATFORM_API_BASE}/tracking/v1/agent-connected`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  }
}
