import { z } from 'zod';
import fetch from 'node-fetch';
import { handleApiResponse, formatSuccessMessage } from '../response-handler.js';
import { docTypeSchema, sdkFeatureSchema, sdkLanguageSchema } from '@insforge/shared-schemas';
import type { RegisterContext } from './types.js';

export function registerDocsTools(ctx: RegisterContext): void {
  const { API_BASE_URL, registerTool, withUsageTracking, getApiKey, addBackgroundContext } = ctx;

  // Helper: fetch general documentation
  const fetchDocumentation = async (docType: string): Promise<string> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/docs/${docType}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.status === 404) {
        throw new Error('Documentation not found. This feature may not be supported in your project version. Please contact the Insforge team for assistance.');
      }

      const result = await handleApiResponse(response);

      if (result && typeof result === 'object' && 'content' in result) {
        let content = result.content as string;
        content = content.replace(/http:\/\/localhost:7130/g, API_BASE_URL);
        content = content.replace(/https:\/\/your-app\.region\.insforge\.app/g, API_BASE_URL);
        content = content.replace(/https:\/\/your-app\.insforge\.app/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${docType} documentation: ${errMsg}`, { cause: error });
    }
  };

  // Helper: fetch SDK documentation
  const fetchSDKDocumentation = async (feature: string, language: string): Promise<string> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/docs/${feature}/${language}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.status === 404) {
        throw new Error('Documentation not found. This feature may not be supported in your project version. Please contact the Insforge team for assistance.');
      }

      const result = await handleApiResponse(response);

      if (result && typeof result === 'object' && 'content' in result) {
        let content = result.content as string;
        content = content.replace(/http:\/\/localhost:7130/g, API_BASE_URL);
        content = content.replace(/https:\/\/your-app\.region\.insforge\.app/g, API_BASE_URL);
        content = content.replace(/https:\/\/your-app\.insforge\.app/g, API_BASE_URL);
        return content;
      }

      throw new Error('Invalid response format from documentation endpoint');
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new Error(`Unable to retrieve ${feature}-${language} documentation: ${errMsg}`, { cause: error });
    }
  };

  // --------------------------------------------------
  // INSTRUCTION TOOLS
  // --------------------------------------------------

  registerTool(
    'fetch-docs',
    'Fetch Insforge documentation. Use "instructions" for essential backend setup (MANDATORY FIRST), or select specific SDK docs for database, auth, storage, functions, or AI integration.',
    { docType: docTypeSchema },
    withUsageTracking('fetch-docs', async ({ docType }) => {
      try {
        const content = await fetchDocumentation(docType);
        return await addBackgroundContext({
          content: [{ type: 'text', text: content }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        if (errMsg.includes('404') || errMsg.toLowerCase().includes('not found')) {
          return {
            content: [{
              type: 'text' as const,
              text: `Documentation for "${docType}" is not available. This is likely because your backend version is too old and doesn't support this documentation endpoint yet. This won't affect the functionality of the tools - they will still work correctly.`,
            }],
          };
        }
        return {
          content: [{ type: 'text' as const, text: `Error fetching ${docType} documentation: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'fetch-sdk-docs',
    `Fetch Insforge SDK documentation for a specific feature and language combination.

Supported features: ${sdkFeatureSchema.options.join(', ')}
Supported languages: ${sdkLanguageSchema.options.join(', ')}`,
    { sdkFeature: sdkFeatureSchema, sdkLanguage: sdkLanguageSchema },
    withUsageTracking('fetch-sdk-docs', async ({ sdkFeature, sdkLanguage }) => {
      try {
        const content = await fetchSDKDocumentation(sdkFeature, sdkLanguage);
        return await addBackgroundContext({
          content: [{ type: 'text', text: content }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        if (errMsg.includes('404') || errMsg.toLowerCase().includes('not found')) {
          return {
            content: [{
              type: 'text' as const,
              text: `Documentation for "${sdkFeature}-${sdkLanguage}" is not available. This is likely because your backend version is too old and doesn't support this documentation endpoint yet. This won't affect the functionality of the tools - they will still work correctly.`,
            }],
          };
        }
        return {
          content: [{ type: 'text' as const, text: `Error fetching ${sdkFeature}-${sdkLanguage} documentation: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );

  registerTool(
    'get-anon-key',
    'Generate an anonymous JWT token that never expires. Requires admin API key. Use this for client-side applications that need public access.',
    {
      apiKey: z.string().optional().describe('API key for authentication (optional if provided via --api_key)'),
    },
    withUsageTracking('get-anon-key', async ({ apiKey }) => {
      try {
        const actualApiKey = getApiKey(apiKey);
        const response = await fetch(`${API_BASE_URL}/api/auth/tokens/anon`, {
          method: 'POST',
          headers: {
            'x-api-key': actualApiKey,
            'Content-Type': 'application/json',
          },
        });

        const result = await handleApiResponse(response);
        return await addBackgroundContext({
          content: [{ type: 'text', text: formatSuccessMessage('Anonymous token generated', result) }],
        });
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{ type: 'text', text: `Error generating anonymous token: ${errMsg}` }],
          isError: true,
        };
      }
    })
  );
}
