/**
 * Shared file utilities used across the application
 */

/**
 * Extract the file name from a file path (works with both Windows and Unix paths)
 */
export function getFileName(filePath: string): string {
  if (!filePath) return 'Unknown file';
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || filePath;
}

/**
 * Format file size for display
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Truncate a hash for display
 */
export function truncateHash(hash: string, length: number = 16): string {
  if (!hash) return '';
  if (hash.length <= length) return hash;
  return `${hash.substring(0, length)}...`;
}
