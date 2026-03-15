// Helper functions to handle traditional REST response format

interface ErrorResponse {
  error?: string;
  message?: string;
  statusCode?: number;
  nextAction?: string;
}

// Type guard to check if the value is an ErrorResponse
function isErrorResponse(value: unknown): value is ErrorResponse {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  const hasMessage = typeof v.message === 'string';
  const hasError = typeof v.error === 'string';
  const hasStatusCode = typeof v.statusCode === 'number';
  const hasNextAction = !('nextAction' in v) || typeof v.nextAction === 'string';
  return (hasMessage || hasError || hasStatusCode) && hasNextAction;
}

// Minimal type for fetch Response
interface FetchResponse {
  ok: boolean;
  json(): Promise<unknown>;
}

export async function handleApiResponse(response: FetchResponse): Promise<unknown> {
  const responseData = await response.json();

  if (!response.ok) {
    if (isErrorResponse(responseData)) {
      let fullMessage = responseData.message ?? responseData.error ?? 'Unknown error';
      if (typeof responseData.nextAction === 'string' && responseData.nextAction.length > 0) {
        fullMessage += `. ${responseData.nextAction}`;
      }
      throw new Error(fullMessage);
    }
    throw new Error('Unknown error');
  }

  return responseData;
}

// Type guard to check if the value has a message property
function hasMessageProperty(value: unknown): value is { message: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    'message' in value &&
    typeof (value as { message: unknown }).message === 'string'
  );
}

export function formatSuccessMessage(operation: string, data: unknown): string {
  if (hasMessageProperty(data)) {
    return `${data.message}\n${JSON.stringify(data, null, 2)}`;
  }
  return `${operation} completed successfully:\n${JSON.stringify(data, null, 2)}`;
}