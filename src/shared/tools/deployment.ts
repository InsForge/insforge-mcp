import { z } from 'zod';
import fetch from 'node-fetch';
import { promises as fs, createWriteStream, createReadStream } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import archiver from 'archiver';
import FormData from 'form-data';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import {
  StartDeploymentRequest,
  CreateDeploymentResponse,
  startDeploymentRequestSchema,
} from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';
import { shellEsc } from './utils.js';

export function registerDeploymentTools(ctx: RegisterContext): void {
  const { API_BASE_URL, isRemote, registerTool, withUsageTracking, getApiKey, addBackgroundContext } = ctx;

  // --------------------------------------------------
  // CONTAINER LOGS TOOLS
  // --------------------------------------------------

  registerTool(
    'get-container-logs',
    'Get latest logs from a specific container/service. Use this to help debug problems with your app.',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
      source: z.enum(['insforge.logs', 'postgREST.logs', 'postgres.logs', 'function.logs']).describe('Log source to retrieve'),
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
          content: [{ type: 'text', text: formatSuccessMessage(`Latest logs from ${source}`, result) }],
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
      'Prepare a deployment by creating a presigned upload URL. Returns shell commands for the agent to execute locally: zip the source directory and upload to cloud storage. After uploading, call the start-deployment tool to trigger the build.',
      {
        sourceDirectory: z.string().describe('Absolute path to the source directory containing files to deploy (e.g., /Users/name/project). Do not use relative paths like "."'),
      },
      withUsageTracking('create-deployment', async ({ sourceDirectory }) => {
        try {
          const isAbsolutePath = sourceDirectory.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(sourceDirectory);
          if (!isAbsolutePath) {
            return {
              content: [{
                type: 'text' as const,
                text: `Error: sourceDirectory must be an absolute path, not a relative path like "${sourceDirectory}". Please provide the full path to the source directory (e.g., /Users/name/project on macOS/Linux or C:\\Users\\name\\project on Windows).`,
              }],
              isError: true,
            };
          }

          const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
          });

          const createResult: CreateDeploymentResponse = await handleApiResponse(createResponse);
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
  -x "node_modules/*" ".git/*" ".next/*" ".env" ".env.local" "dist/*" "build/*" ".DS_Store" "*.log"
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
      withUsageTracking('start-deployment', async ({ deploymentId, projectSettings, envVars, meta }) => {
        try {
          const startBody: StartDeploymentRequest = {};
          if (projectSettings) startBody.projectSettings = projectSettings;
          if (envVars) startBody.envVars = envVars;
          if (meta) startBody.meta = meta;

          const startResponse = await fetch(`${API_BASE_URL}/api/deployments/${encodeURIComponent(deploymentId)}/start`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(startBody),
          });

          const startResult = await handleApiResponse(startResponse);
          return await addBackgroundContext({
            content: [{
              type: 'text',
              text: formatSuccessMessage('Deployment started', startResult) + '\n\nNote: You can check deployment status by querying the system.deployments table.',
            }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error starting deployment: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  } else {
    // Local mode: zip, upload, and trigger deployment directly
    registerTool(
      'create-deployment',
      'Deploy source code from a directory. This tool zips files, uploads to cloud storage, and triggers deployment with optional environment variables and project settings.',
      {
        sourceDirectory: z.string().describe('Absolute path to the source directory containing files to deploy (e.g., /Users/name/project or C:\\Users\\name\\project). Do not use relative paths like "."'),
        ...startDeploymentRequestSchema.shape,
      },
      withUsageTracking('create-deployment', async ({ sourceDirectory, projectSettings, envVars, meta }) => {
        try {
          const isAbsolutePath = sourceDirectory.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(sourceDirectory);
          if (!isAbsolutePath) {
            return {
              content: [{
                type: 'text' as const,
                text: `Error: sourceDirectory must be an absolute path, not a relative path like "${sourceDirectory}". Please provide the full path to the source directory (e.g., /Users/name/project on macOS/Linux or C:\\Users\\name\\project on Windows).`,
              }],
              isError: true,
            };
          }

          try {
            const stats = await fs.stat(sourceDirectory);
            if (!stats.isDirectory()) {
              return {
                content: [{
                  type: 'text' as const,
                  text: `Error: "${sourceDirectory}" is not a directory. Please provide a path to a directory containing the source code.`,
                }],
                isError: true,
              };
            }
          } catch {
            return {
              content: [{
                type: 'text' as const,
                text: `Error: Directory "${sourceDirectory}" does not exist or is not accessible. Please verify the path is correct.`,
              }],
              isError: true,
            };
          }

          const resolvedSourceDir = sourceDirectory;

          const createResponse = await fetch(`${API_BASE_URL}/api/deployments`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
          });

          const createResult: CreateDeploymentResponse = await handleApiResponse(createResponse);
          const { id: deploymentId, uploadUrl, uploadFields } = createResult;

          // Write archive to a temp file so we know the size before uploading
          // (S3 presigned POSTs require Content-Length; streaming without it fails)
          const tmpZipPath = join(tmpdir(), `insforge-deploy-${deploymentId}.zip`);

          try {
            await new Promise<void>((resolve, reject) => {
              const archive = archiver('zip', { zlib: { level: 9 } });
              const output = createWriteStream(tmpZipPath);

              output.on('close', resolve);
              output.on('error', reject);
              archive.on('error', reject);

              const excludePatterns = ['node_modules', '.git', '.next', '.env', '.env.local', 'dist', 'build', '.DS_Store'];

              archive.directory(resolvedSourceDir, false, (entry) => {
                const normalizedName = entry.name.replace(/\\/g, '/');

                for (const pattern of excludePatterns) {
                  if (
                    normalizedName.startsWith(pattern + '/') ||
                    normalizedName === pattern ||
                    normalizedName.endsWith('/' + pattern) ||
                    normalizedName.includes('/' + pattern + '/')
                  ) {
                    return false;
                  }
                }

                if (normalizedName.endsWith('.log')) return false;
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

          const startBody: StartDeploymentRequest = {};
          if (projectSettings) startBody.projectSettings = projectSettings;
          if (envVars) startBody.envVars = envVars;
          if (meta) startBody.meta = meta;

          const startResponse = await fetch(`${API_BASE_URL}/api/deployments/${encodeURIComponent(deploymentId)}/start`, {
            method: 'POST',
            headers: {
              'x-api-key': getApiKey(),
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(startBody),
          });

          const startResult = await handleApiResponse(startResponse);
          return await addBackgroundContext({
            content: [{
              type: 'text',
              text: formatSuccessMessage('Deployment started', startResult) + '\n\nNote: You can check deployment status by querying the system.deployments table.',
            }],
          });
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
          return {
            content: [{ type: 'text', text: `Error creating deployment: ${errMsg}` }],
            isError: true,
          };
        }
      })
    );
  }
}
