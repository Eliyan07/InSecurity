import { describe, it, expect } from 'vitest';
import { formatError } from '../error';

describe('formatError', () => {
  it('extracts message from Error instance', () => {
    expect(formatError(new Error('test message'))).toBe('test message');
  });

  it('returns string errors as-is', () => {
    expect(formatError('raw string error')).toBe('raw string error');
  });

  it('extracts message from object with message property', () => {
    expect(formatError({ message: 'object error' })).toBe('object error');
  });

  it('converts numbers to string', () => {
    expect(formatError(42)).toBe('42');
  });

  it('converts null to string', () => {
    expect(formatError(null)).toBe('null');
  });

  it('converts undefined to string', () => {
    expect(formatError(undefined)).toBe('undefined');
  });

  it('converts boolean to string', () => {
    expect(formatError(false)).toBe('false');
  });

  it('handles nested Error types (TypeError)', () => {
    expect(formatError(new TypeError('type error'))).toBe('type error');
  });

  it('handles object with non-string message', () => {
    expect(formatError({ message: 123 })).toBe('123');
  });

  it('handles empty Error message', () => {
    expect(formatError(new Error(''))).toBe('');
  });
});
