import { describe, it, expect } from 'vitest';
import { getFileName, formatFileSize, truncateHash } from '../file';

describe('getFileName', () => {
  it('extracts filename from Windows path', () => {
    expect(getFileName('C:\\Users\\test\\file.exe')).toBe('file.exe');
  });

  it('extracts filename from Unix path', () => {
    expect(getFileName('/home/user/file.txt')).toBe('file.txt');
  });

  it('extracts filename from mixed separators', () => {
    expect(getFileName('C:/Users/test\\file.exe')).toBe('file.exe');
  });

  it('returns "Unknown file" for empty string', () => {
    expect(getFileName('')).toBe('Unknown file');
  });

  it('returns the filename itself when no path', () => {
    expect(getFileName('file.exe')).toBe('file.exe');
  });

  it('handles deeply nested paths', () => {
    expect(getFileName('C:\\a\\b\\c\\d\\e\\deep.dll')).toBe('deep.dll');
  });

  it('handles path ending with separator', () => {
    // When path ends with separator, last split element is empty, falls back to filePath
    const result = getFileName('C:\\folder\\');
    expect(result).toBeTruthy();
  });
});

describe('formatFileSize', () => {
  it('returns "0 B" for zero bytes', () => {
    expect(formatFileSize(0)).toBe('0 B');
  });

  it('formats bytes correctly', () => {
    expect(formatFileSize(500)).toBe('500 B');
  });

  it('formats 1 byte', () => {
    expect(formatFileSize(1)).toBe('1 B');
  });

  it('formats kilobytes', () => {
    expect(formatFileSize(1024)).toBe('1 KB');
  });

  it('formats fractional kilobytes', () => {
    expect(formatFileSize(1536)).toBe('1.5 KB');
  });

  it('formats megabytes', () => {
    expect(formatFileSize(1048576)).toBe('1 MB');
  });

  it('formats gigabytes', () => {
    expect(formatFileSize(1073741824)).toBe('1 GB');
  });

  it('formats large file sizes', () => {
    const result = formatFileSize(5 * 1073741824);
    expect(result).toBe('5 GB');
  });
});

describe('truncateHash', () => {
  it('returns short hash unchanged', () => {
    expect(truncateHash('abc', 16)).toBe('abc');
  });

  it('returns exact-length hash unchanged', () => {
    expect(truncateHash('abcdefghijklmnop', 16)).toBe('abcdefghijklmnop');
  });

  it('truncates long hash with ellipsis', () => {
    const hash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    const result = truncateHash(hash, 16);
    expect(result).toBe('b94d27b9934d3e08...');
  });

  it('returns empty string for empty input', () => {
    expect(truncateHash('')).toBe('');
  });

  it('uses default length of 16', () => {
    const hash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    const result = truncateHash(hash);
    expect(result).toBe('b94d27b9934d3e08...');
  });
});
