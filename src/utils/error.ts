/**
 * Shared error handling utilities
 */

/**
 * Format an error for display - handles various error types consistently
 */
export function formatError(e: unknown): string {
  if (e instanceof Error) {
    return e.message;
  }
  if (typeof e === 'string') {
    return e;
  }
  if (e && typeof e === 'object' && 'message' in e) {
    return String((e as { message: unknown }).message);
  }
  return String(e);
}
