import { z } from 'zod';
import fetch from 'node-fetch';
import { createHash } from 'crypto';
import { promises as fs, createWriteStream, createReadStream } from 'fs';
import { tmpdir } from 'os';
import { join, relative, sep } from 'path';
import archiver from 'archiver';
import FormData from 'form-data';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import {
  createDeploymentResponseSchema,
  createDirectDeploymentResponseSchema,
  startDeploymentRequestSchema,
} from '@insforge/shared-schemas';
import type {
  CreateDeploymentResponse,
  CreateDirectDeploymentResponse,
  DeploymentManifestFile,
  DeploymentManifestFileEntry,
  StartDeploymentRequest,
} from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';
import { shellEsc } from './utils.js';

const DIRECT_DEPLOYMENT_MIN_VERSION = '2.0.6';
const DEFAULT_DIRECT_UPLOAD_CONCURRENCY = 8;
const MAX_DIRECT_UPLOAD_CONCURRENCY = 32;
const EXCLUDED_DEPLOYMENT_SEGMENTS = new Set([
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  '.insforge',
]);

interface LocalDeploymentFile extends DeploymentManifestFileEntry {
  absolutePath: string;
}

type DirectDeploymentSession = CreateDirectDeploymentResponse;

class DirectDeploymentUnsupportedError extends Error {
  constructor() {
    super('Direct deployment endpoints are not available on this backend');
    this.name = 'DirectDeploymentUnsupportedError';
  }
}

function isInsforgeCloudApiBaseUrl(apiBaseUrl: string): boolean {
  try {
    return new URL(apiBaseUrl).hostname.endsWith('.insforge.app');
  } catch {
    return false;
  }
}

function isAbsoluteSourcePath(sourceDirectory: string): boolean {
  return sourceDirectory.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(sourceDirectory);
}

function supportsDirectDeploymentVersion(backendVersion: string): boolean {
  const cleanVersion = backendVersion.replace(/^v/, '').split('-')[0];
  const [major = 0, minor = 0, patch = 0] = cleanVersion.split('.').map(Number);
  const [minMajor, minMinor, minPatch] = DIRECT_DEPLOYMENT_MIN_VERSION.split('.').map(Number);

  if (major !== minMajor) return major > minMajor;
  if (minor !== minMinor) return minor > minMinor;
  return patch >= minPatch;
}

function shouldExcludeDeploymentPath(normalizedName: string): boolean {
  const segments = normalizedName.split('/');

  if (segments.some((segment) => segment === '.env' || segment.startsWith('.env.'))) {
    return true;
  }

  if (segments.some((segment) => EXCLUDED_DEPLOYMENT_SEGMENTS.has(segment))) {
    return true;
  }

  return (
    normalizedName === '.DS_Store' ||
    normalizedName.endsWith('/.DS_Store') ||
    normalizedName.endsWith('.log')
  );
}

function normalizeRelativePath(rootDirectory: string, absolutePath: string): string {
  return relative(rootDirectory, absolutePath).split(sep).join('/').replace(/\\/g, '/');
}

async function hashFile(filePath: string): Promise<{ sha: string; size: number }> {
  const hash = createHash('sha1');
  let size = 0;

  for await (const chunk of createReadStream(filePath)) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    hash.update(buffer);
  }

  return { sha: hash.digest('hex'), size };
}

function parseCreateDeploymentResponse(obj: unknown): CreateDeploymentResponse {
  const result = createDeploymentResponseSchema.safeParse(obj);
  if (!result.success) {
    throw new Error('Unexpected response format from deployments endpoint');
  }

  return result.data;
}

function parseCreateDirectDeploymentResponse(obj: unknown): DirectDeploymentSession {
  const result = createDirectDeploymentResponseSchema.safeParse(obj);
  if (!result.success) {
    throw new Error('Unexpected response format from direct deployments endpoint');
  }

  return result.data;
}

function getDirectUploadConcurrency(): number {
  const parsed = Number.parseInt(process.env.INSFORGE_DEPLOY_UPLOAD_CONCURRENCY ?? '', 10);
  const requested =
    Number.isSafeInteger(parsed) && parsed > 0 ? parsed : DEFAULT_DIRECT_UPLOAD_CONCURRENCY;
  return Math.min(requested, MAX_DIRECT_UPLOAD_CONCURRENCY);
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<void>
): Promise<void> {
  let nextIndex = 0;

  async function runWorker(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex++;
      await worker(items[index], index);
    }
  }

  const workerCount = Math.min(concurrency, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
}

async function collectDeploymentFiles(sourceDirectory: string): Promise<LocalDeploymentFile[]> {
  const files: LocalDeploymentFile[] = [];

  async function walk(currentDirectory: string): Promise<void> {
    const entries = await fs.readdir(currentDirectory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absolutePath = join(currentDirectory, entry.name);
      const normalizedPath = normalizeRelativePath(sourceDirectory, absolutePath);

      if (!normalizedPath || shouldExcludeDeploymentPath(normalizedPath)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const { sha, size } = await hashFile(absolutePath);
      files.push({
        absolutePath,
        path: normalizedPath,
        sha,
        size,
      });
    }
  }

  await walk(sourceDirectory);
  return files;
}

function buildStartBody(input: {
  projectSettings?: StartDeploymentRequest['projectSettings'];
  envVars?: StartDeploymentRequest['envVars'];
  meta?: StartDeploymentRequest['meta'];
}): StartDeploymentRequest {
  const startBody: StartDeploymentRequest = {};
  if (input.projectSettings) startBody.projectSettings = input.projectSettings;
  if (input.envVars) startBody.envVars = input.envVars;
  if (input.meta) startBody.meta = input.meta;
  return startBody;
}

async function createDirectDeploymentSession(
  API_BASE_URL: string,
  apiKey: string,
  files: DeploymentManifestFileEntry[]
): Promise<DirectDeploymentSession> {
  const response = await fetch(`${API_BASE_URL}/api/deployments/direct`, {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ files }),
  });

  if (response.status === 404) {
    throw new DirectDeploymentUnsupportedError();
  }

  const result = await handleApiResponse(response);
  return parseCreateDirectDeploymentResponse(result);
}

async function uploadDeploymentFileContent(
  API_BASE_URL: string,
  apiKey: string,
  deploymentId: string,
  file: DeploymentManifestFile,
  localFile: LocalDeploymentFile
): Promise<void> {
  const response = await fetch(
    `${API_BASE_URL}/api/deployments/${encodeURIComponent(deploymentId)}/files/${encodeURIComponent(file.fileId)}/content`,
    {
      method: 'PUT',
      headers: {
        'x-api-key': apiKey,
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(localFile.size),
      },
      body: createReadStream(localFile.absolutePath),
    }
  );

  if (response.status === 404) {
    throw new DirectDeploymentUnsupportedError();
  }

  await handleApiResponse(response);
}

async function startDeployment(
  API_BASE_URL: string,
  apiKey: string,
  deploymentId: string,
  startBody: StartDeploymentRequest
): Promise<unknown> {
  const response = await fetch(
    `${API_BASE_URL}/api/deployments/${encodeURIComponent(deploymentId)}/start`,
    {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(startBody),
    }
  );

  return handleApiResponse(response);
}

async function deployDirect(
  API_BASE_URL: string,
  apiKey: string,
  sourceDirectory: string,
  startBody: StartDeploymentRequest
): Promise<{
  deploymentId: string;
  fileCount: number;
  uploadConcurrency: number;
  startResult: unknown;
}> {
  const files = await collectDeploymentFiles(sourceDirectory);
  if (files.length === 0) {
    throw new Error('No deployable files found in source directory after applying exclusions.');
  }

  const manifestFiles = files.map(({ path, sha, size }) => ({ path, sha, size }));
  const createResult = await createDirectDeploymentSession(API_BASE_URL, apiKey, manifestFiles);
  const deploymentId = String(createResult.id);
  const localFileByPath = new Map(files.map((file) => [file.path, file] as const));
  const uploadConcurrency = getDirectUploadConcurrency();

  await runWithConcurrency(createResult.files, uploadConcurrency, async (file) => {
    const localFile = localFileByPath.get(file.path);
    if (!localFile) {
      throw new Error(`Direct deployment response included unknown file path: ${file.path}`);
    }
    if (localFile.sha !== file.sha || localFile.size !== file.size) {
      throw new Error(`Direct deployment response did not match local file metadata: ${file.path}`);
    }

    await uploadDeploymentFileContent(API_BASE_URL, apiKey, deploymentId, file, localFile);
  });

  const startResult = await startDeployment(API_BASE_URL, apiKey, deploymentId, startBody);
  return { deploymentId, fileCount: files.length, uploadConcurrency, startResult };
}

function buildRemoteDirectUploadInstructions(
  API_BASE_URL: string,
  sourceDirectory: string
): string {
  const escapedDir = shellEsc(sourceDirectory);
  const apiBaseUrlJson = JSON.stringify(API_BASE_URL);

  return `Direct deployment upload is available for this backend.

Please execute the following command locally from a shell that has INSFORGE_API_KEY set, then call the \`start-deployment\` tool with the deployment ID printed by the script. Set \`INSFORGE_DEPLOY_UPLOAD_CONCURRENCY\` if you want to tune parallel uploads; the default is 8 and the maximum is 32.

\`\`\`bash
cd ${escapedDir}
INSFORGE_API_KEY="\${INSFORGE_API_KEY:?Set INSFORGE_API_KEY to your InsForge API key}" node --input-type=module <<'NODE'
const { createHash } = await import('node:crypto');
const { createReadStream } = await import('node:fs');
const fs = await import('node:fs/promises');
const path = await import('node:path');

const API_BASE_URL = ${apiBaseUrlJson};
const API_KEY = process.env.INSFORGE_API_KEY;
const DEFAULT_UPLOAD_CONCURRENCY = 8;
const MAX_UPLOAD_CONCURRENCY = 32;
const EXCLUDED_SEGMENTS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '.insforge']);

function shouldExcludeDeploymentPath(normalizedName) {
  const segments = normalizedName.split('/');
  if (segments.some((segment) => segment === '.env' || segment.startsWith('.env.'))) return true;
  if (segments.some((segment) => EXCLUDED_SEGMENTS.has(segment))) return true;
  return normalizedName === '.DS_Store' || normalizedName.endsWith('/.DS_Store') || normalizedName.endsWith('.log');
}

async function readJsonResponse(response) {
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!response.ok) {
    const message = data && typeof data === 'object' ? data.message || data.error : null;
    throw new Error(message || 'Request failed with status ' + response.status);
  }
  return data;
}

async function api(pathname, init = {}) {
  const headers = {
    'x-api-key': API_KEY,
    ...(init.headers || {}),
  };
  const response = await fetch(API_BASE_URL + pathname, { ...init, headers });
  return readJsonResponse(response);
}

function getUploadConcurrency() {
  const parsed = Number.parseInt(process.env.INSFORGE_DEPLOY_UPLOAD_CONCURRENCY || '', 10);
  const requested = Number.isSafeInteger(parsed) && parsed > 0 ? parsed : DEFAULT_UPLOAD_CONCURRENCY;
  return Math.min(requested, MAX_UPLOAD_CONCURRENCY);
}

async function runWithConcurrency(items, concurrency, worker) {
  let nextIndex = 0;

  async function runWorker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      await worker(items[index], index);
    }
  }

  const workerCount = Math.min(concurrency, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
}

async function hashFile(filePath) {
  const hash = createHash('sha1');
  let size = 0;
  for await (const chunk of createReadStream(filePath)) {
    size += chunk.length;
    hash.update(chunk);
  }
  return { sha: hash.digest('hex'), size };
}

async function collectFiles(rootDirectory) {
  const files = [];

  async function walk(currentDirectory) {
    const entries = await fs.readdir(currentDirectory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absolutePath = path.join(currentDirectory, entry.name);
      const normalizedPath = path.relative(rootDirectory, absolutePath).split(path.sep).join('/').replace(/\\\\/g, '/');

      if (!normalizedPath || shouldExcludeDeploymentPath(normalizedPath)) continue;
      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }
      if (!entry.isFile()) continue;

      const { sha, size } = await hashFile(absolutePath);
      files.push({ absolutePath, path: normalizedPath, sha, size });
    }
  }

  await walk(rootDirectory);
  return files;
}

async function uploadFile(deploymentId, manifestFile, localFile) {
  const response = await fetch(
    API_BASE_URL +
      '/api/deployments/' +
      encodeURIComponent(deploymentId) +
      '/files/' +
      encodeURIComponent(manifestFile.fileId) +
      '/content',
    {
      method: 'PUT',
      headers: {
        'x-api-key': API_KEY,
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(localFile.size),
      },
      body: createReadStream(localFile.absolutePath),
      duplex: 'half',
    }
  );

  await readJsonResponse(response);
}

const rootDirectory = process.cwd();
const localFiles = await collectFiles(rootDirectory);
if (localFiles.length === 0) throw new Error('No deployable files found after applying exclusions.');

const createResult = await api('/api/deployments/direct', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    files: localFiles.map(({ path, sha, size }) => ({ path, sha, size })),
  }),
});

if (!createResult || !Array.isArray(createResult.files)) {
  throw new Error('Direct deployment endpoint returned an unexpected response.');
}

const deploymentId = createResult.id;
const localFileByPath = new Map(localFiles.map((file) => [file.path, file]));
const uploadConcurrency = getUploadConcurrency();
console.log('Created deployment. Deployment ID: ' + deploymentId);

await runWithConcurrency(createResult.files, uploadConcurrency, async (manifestFile) => {
  const localFile = localFileByPath.get(manifestFile.path);
  if (!localFile) throw new Error('Backend returned an unknown file path: ' + manifestFile.path);
  if (localFile.sha !== manifestFile.sha || localFile.size !== manifestFile.size) {
    throw new Error('Backend file metadata mismatch for: ' + manifestFile.path);
  }
  await uploadFile(deploymentId, manifestFile, localFile);
});

console.log('Deployment files uploaded. Deployment ID: ' + deploymentId);
console.log('Uploaded ' + createResult.files.length + ' files through direct deployment proxy with concurrency ' + uploadConcurrency + '.');
NODE
\`\`\`

After the script succeeds, call the \`start-deployment\` tool with the printed deployment ID.

If the upload is interrupted after the deployment ID is printed, query \`deployments.files\` with the raw SQL tool for that \`deployment_id\` to inspect \`uploaded_at\`. You can rerun \`create-deployment\` to create a fresh deployment, or upload missing file IDs to \`PUT /api/deployments/:id/files/:fileId/content\` using the queried manifest rows.`;
}

export function registerDeploymentTools(ctx: RegisterContext): void {
  const {
    API_BASE_URL,
    backendVersion,
    isRemote,
    registerTool,
    withUsageTracking,
    getApiKey,
    addBackgroundContext,
  } = ctx;
  const supportsDirectDeployment = supportsDirectDeploymentVersion(backendVersion);

  // --------------------------------------------------
  // CONTAINER LOGS TOOLS
  // --------------------------------------------------

  registerTool(
    'get-container-logs',
    'Get latest logs from a specific container/service. Use this to help debug problems with your app.',
    {
      apiKey: z
        .string()
        .optional()
        .describe('API key for authentication (optional if provided via --api_key)'),
      source: z
        .enum(['insforge.logs', 'postgREST.logs', 'postgres.logs', 'function.logs'])
        .describe('Log source to retrieve'),
      limit: z.number().optional().default(20).describe('Number of logs to return (default: 20)'),
    },
    withUsageTracking('get-container-logs', async ({ apiKey, source, limit }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const queryParams = new URLSearchParams();
        if (limit) queryParams.append('limit', limit.toString());

        let response = await fetch(`${API_BASE_URL}/api/logs/${source}?${queryParams}`, {
          method: 'GET',
          headers: { 'x-api-key': actualApiKey },
        });

        // Fallback to legacy endpoint if 404
        if (response.status === 404) {
          response = await fetch(`${API_BASE_URL}/api/logs/analytics/${source}?${queryParams}`, {
            method: 'GET',
            headers: { 'x-api-key': actualApiKey },
          });
        }

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [
            { type: 'text', text: formatSuccessMessage(`Latest logs from ${source}`, result) },
          ],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error retrieving container logs: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  // --------------------------------------------------
  // DEPLOYMENT TOOLS
  // --------------------------------------------------

  if (isRemote) {
    // Remote mode: prepare deployment and return instructions for agent to execute locally
    registerTool(
      'create-deployment',
      'Prepare a deployment upload. Direct-capable backends return direct file upload commands. Older backends use the legacy zip upload flow. After uploading, call the start-deployment tool to trigger the build.',
      {
        sourceDirectory: z
          .string()
          .describe(
            'Absolute path to the source directory containing files to deploy (e.g., /Users/name/project). Do not use relative paths like "."'
          ),
      },
      withUsageTracking('create-deployment', async ({ sourceDirectory }) => {
        try {
          if (!isAbsoluteSourcePath(sourceDirectory)) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Error: sourceDirectory must be an absolute path, not a relative path like "${sourceDirectory}". Please provide the full path to the source directory (e.g., /Users/name/project on macOS/Linux or C:\\Users\\name\\project on Windows).`,
                },
              ],
              isError: true,
            };
          }

          if (supportsDirectDeployment) {
            return {
              content: [
                {
                  type: 'text',
                  text: buildRemoteDirectUploadInstructions(API_BASE_URL, sourceDirectory),
                },
              ],
            };
          }

          const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
          });

          const createResult = parseCreateDeploymentResponse(
            await handleApiResponse(createResponse)
          );
          const { id: deploymentId, uploadUrl, uploadFields } = createResult;

          const esc = shellEsc;
          const curlFields = Object.entries(uploadFields)
            .map(([key, value]) => `-F ${esc(`${key}=${value}`)}`)
            .join(' \\\n  ');

          const escapedDir = esc(sourceDirectory);
          const tmpZip = `/tmp/insforge-deploy-${deploymentId}.zip`;

          const instructions = `Deployment prepared successfully. Deployment ID: ${deploymentId}

Please execute the following commands locally, then call the \`start-deployment\` tool:

## Step 1: Zip the source directory
\`\`\`bash
cd ${escapedDir} && zip -r ${tmpZip} . \
  -x "node_modules/*" ".git/*" ".next/*" ".env*" "dist/*" "build/*" ".insforge/*" ".DS_Store" "*.log"
\`\`\`

## Step 2: Upload the zip file
\`\`\`bash
curl -X POST ${esc(uploadUrl)} \
  ${curlFields} \
  -F 'file=@${tmpZip};type=application/zip'
\`\`\`

## Step 3: Clean up
\`\`\`bash
rm /tmp/insforge-deploy-${deploymentId}.zip
\`\`\`

## Step 4: Trigger the build
Call the \`start-deployment\` tool with deploymentId: "${deploymentId}"

Run each step in order. If any step fails, do not proceed to the next step.`;

          return {
            content: [{ type: 'text', text: instructions }],
          };
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error preparing deployment: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );

    // Remote mode: start-deployment tool triggers the build via API
    registerTool(
      'start-deployment',
      'Trigger a deployment build after uploading source code. Use this after executing the upload commands from create-deployment.',
      {
        deploymentId: z.string().describe('The deployment ID returned by create-deployment'),
        ...startDeploymentRequestSchema.shape,
      },
      withUsageTracking(
        'start-deployment',
        async ({ deploymentId, projectSettings, envVars, meta }) => {
          try {
            const startBody: StartDeploymentRequest = {};
            if (projectSettings) startBody.projectSettings = projectSettings;
            if (envVars) startBody.envVars = envVars;
            if (meta) startBody.meta = meta;

            const startResponse = await fetch(
              `${API_BASE_URL}/api/deployments/${encodeURIComponent(deploymentId)}/start`,
              {
                method: 'POST',
                headers: {
                  'x-api-key': getApiKey(),
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify(startBody),
              }
            );

            const startResult = await handleApiResponse(startResponse);
            return await addBackgroundContext({
              content: [
                {
                  type: 'text',
                  text:
                    formatSuccessMessage('Deployment started', startResult) +
                    `\n\n${
                      supportsDirectDeployment
                        ? isInsforgeCloudApiBaseUrl(API_BASE_URL)
                          ? 'Note: You can check deployment status by querying the deployments.runs table.'
                          : 'Note: For self-hosted direct deployments, check the result in your Vercel dashboard instead of InsForge deployment logs.'
                        : 'Note: You can check deployment status by querying the deployments.runs table.'
                    }`,
                },
              ],
            });
          } catch (error) {
            const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
            return {
              content: [{ type: 'text', text: `Error starting deployment: ${errMsg}` }],
              isError: true,
            };
          }
        }
      )
    );
  } else {
    // Local mode: zip, upload, and trigger deployment directly
    registerTool(
      'create-deployment',
      'Deploy source code from a directory. Uses parallel direct file uploads for direct-capable backends, with legacy zip upload fallback for older projects.',
      {
        sourceDirectory: z
          .string()
          .describe(
            'Absolute path to the source directory containing files to deploy (e.g., /Users/name/project or C:\\Users\\name\\project). Do not use relative paths like "."'
          ),
        ...startDeploymentRequestSchema.shape,
      },
      withUsageTracking(
        'create-deployment',
        async ({ sourceDirectory, projectSettings, envVars, meta }) => {
          try {
            if (!isAbsoluteSourcePath(sourceDirectory)) {
              return {
                content: [
                  {
                    type: 'text' as const,
                    text: `Error: sourceDirectory must be an absolute path, not a relative path like "${sourceDirectory}". Please provide the full path to the source directory (e.g., /Users/name/project on macOS/Linux or C:\\Users\\name\\project on Windows).`,
                  },
                ],
                isError: true,
              };
            }

            try {
              const stats = await fs.stat(sourceDirectory);
              if (!stats.isDirectory()) {
                return {
                  content: [
                    {
                      type: 'text' as const,
                      text: `Error: "${sourceDirectory}" is not a directory. Please provide a path to a directory containing the source code.`,
                    },
                  ],
                  isError: true,
                };
              }
            } catch {
              return {
                content: [
                  {
                    type: 'text' as const,
                    text: `Error: Directory "${sourceDirectory}" does not exist or is not accessible. Please verify the path is correct.`,
                  },
                ],
                isError: true,
              };
            }

            const resolvedSourceDir = sourceDirectory;
            const startBody = buildStartBody({ projectSettings, envVars, meta });

            if (supportsDirectDeployment) {
              try {
                const { fileCount, uploadConcurrency, startResult } = await deployDirect(
                  API_BASE_URL,
                  getApiKey(),
                  resolvedSourceDir,
                  startBody
                );
                const uploadSummary = `Uploaded ${fileCount} files through direct deployment proxy with concurrency ${uploadConcurrency}.`;

                return await addBackgroundContext({
                  content: [
                    {
                      type: 'text',
                      text:
                        formatSuccessMessage('Deployment started', startResult) +
                        `\n\n${uploadSummary}\n\n${
                          isInsforgeCloudApiBaseUrl(API_BASE_URL)
                            ? 'Note: You can check deployment status by querying the deployments.runs table. If file uploads are interrupted, inspect deployments.files with the raw SQL tool to see which files are already uploaded before retrying missing files.'
                            : 'Note: For self-hosted direct deployments, check the result in your Vercel dashboard instead of InsForge deployment logs. If file uploads are interrupted, inspect deployments.files with the raw SQL tool to see which files are already uploaded before retrying missing files.'
                        }`,
                    },
                  ],
                });
              } catch (error) {
                if (!(error instanceof DirectDeploymentUnsupportedError)) {
                  throw error;
                }
                // Backend reported no direct deployment endpoints despite its version.
                // Fall back to the legacy upload path for compatibility.
              }
            }

            const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
              method: 'POST',
              headers: {
                'x-api-key': getApiKey(),
                'Content-Type': 'application/json',
              },
            });

            const createResult = parseCreateDeploymentResponse(
              await handleApiResponse(createResponse)
            );
            const { id: deploymentId, uploadUrl, uploadFields } = createResult;

            // Write the legacy zip to a temp file so we know the size before uploading
            // (S3 presigned POSTs require Content-Length; streaming without it fails)
            const tmpZipPath = join(tmpdir(), `insforge-deploy-${deploymentId}.zip`);

            try {
              await new Promise<void>((resolve, reject) => {
                const archive = archiver('zip', { zlib: { level: 9 } });
                const output = createWriteStream(tmpZipPath);

                output.on('close', resolve);
                output.on('error', reject);
                archive.on('error', reject);

                archive.directory(resolvedSourceDir, false, (entry) => {
                  const normalizedName = entry.name.replace(/\\/g, '/');
                  if (shouldExcludeDeploymentPath(normalizedName)) return false;
                  return entry;
                });

                archive.pipe(output);
                archive.finalize();
              });

              const { size: zipSize } = await fs.stat(tmpZipPath);

              const uploadFormData = new FormData();
              for (const [key, value] of Object.entries(uploadFields)) {
                uploadFormData.append(key, value);
              }
              uploadFormData.append('file', createReadStream(tmpZipPath), {
                filename: 'deployment.zip',
                contentType: 'application/zip',
                knownLength: zipSize,
              });

              const uploadResponse = await fetch(uploadUrl, {
                method: 'POST',
                body: uploadFormData,
                headers: uploadFormData.getHeaders(),
              });

              if (!uploadResponse.ok) {
                const uploadError = await uploadResponse.text();
                throw new Error(`Failed to upload zip file: ${uploadError}`);
              }
            } finally {
              await fs.rm(tmpZipPath, { force: true }).catch(() => undefined);
            }

            const startResult = await startDeployment(
              API_BASE_URL,
              getApiKey(),
              deploymentId,
              startBody
            );
            return await addBackgroundContext({
              content: [
                {
                  type: 'text',
                  text:
                    formatSuccessMessage('Deployment started', startResult) +
                    '\n\nNote: You can check deployment status by querying the deployments.runs table.',
                },
              ],
            });
          } catch (error) {
            const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
            return {
              content: [{ type: 'text', text: `Error creating deployment: ${errMsg}` }],
              isError: true,
            };
          }
        }
      )
    );
  }
}
