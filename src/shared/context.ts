/**
 * Shared context for workspace information
 * Stores workspace roots obtained from MCP client via roots/list
 */

let workspaceRoots: string[] = [];

export function setWorkspaceRoots(roots: string[]) {
  workspaceRoots = roots;
  console.error(`[Context] Workspace roots set: ${roots.join(', ')}`);
}

export function getWorkspaceRoot(): string | undefined {
  return workspaceRoots[0];
}

export function getWorkspaceRoots(): string[] {
  return workspaceRoots;
}
