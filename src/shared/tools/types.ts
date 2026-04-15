/**
 * Shared context passed to each domain tool registration function.
 * Encapsulates all runtime state set up by registerInsforgeTools.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type RegisterToolFn = (toolName: string, ...args: any[]) => boolean;

export type WithUsageTracking = <T extends unknown[], R>(
  toolName: string,
  handler: (...args: T) => Promise<R>
) => (...args: T) => Promise<R>;

export type GetApiKey = (toolApiKey?: string) => string;

export type AddBackgroundContext = <T extends { content: Array<{ type: 'text'; text: string }> }>(
  response: T
) => Promise<T>;

export interface RegisterContext {
  API_BASE_URL: string;
  backendVersion: string;
  isRemote: boolean;
  registerTool: RegisterToolFn;
  withUsageTracking: WithUsageTracking;
  getApiKey: GetApiKey;
  addBackgroundContext: AddBackgroundContext;
}
