import { describe, it, expect } from 'vitest';
import { parseVerdict, getVerdictClass, getVerdictLabel, isThreat } from '../verdict';
import { Verdict } from '../../types/scan';

describe('parseVerdict', () => {
  it('parses "clean" to CLEAN', () => {
    expect(parseVerdict('clean')).toBe(Verdict.CLEAN);
  });

  it('parses "safe" to CLEAN', () => {
    expect(parseVerdict('safe')).toBe(Verdict.CLEAN);
  });

  it('parses "malware" to MALWARE', () => {
    expect(parseVerdict('malware')).toBe(Verdict.MALWARE);
  });

  it('parses "malicious" to MALWARE', () => {
    expect(parseVerdict('malicious')).toBe(Verdict.MALWARE);
  });

  it('parses "virus" to MALWARE', () => {
    expect(parseVerdict('virus')).toBe(Verdict.MALWARE);
  });

  it('parses "suspicious" to SUSPICIOUS', () => {
    expect(parseVerdict('suspicious')).toBe(Verdict.SUSPICIOUS);
  });

  it('parses "pup" to SUSPICIOUS', () => {
    expect(parseVerdict('pup')).toBe(Verdict.SUSPICIOUS);
  });

  it('parses "potentially unwanted" to SUSPICIOUS', () => {
    expect(parseVerdict('potentially unwanted')).toBe(Verdict.SUSPICIOUS);
  });

  it('parses "adware" to SUSPICIOUS', () => {
    expect(parseVerdict('adware')).toBe(Verdict.SUSPICIOUS);
  });

  it('is case insensitive', () => {
    expect(parseVerdict('CLEAN')).toBe(Verdict.CLEAN);
    expect(parseVerdict('Malware')).toBe(Verdict.MALWARE);
    expect(parseVerdict('SUSPICIOUS')).toBe(Verdict.SUSPICIOUS);
  });

  it('trims whitespace', () => {
    expect(parseVerdict('  clean  ')).toBe(Verdict.CLEAN);
    expect(parseVerdict('\tmalware\n')).toBe(Verdict.MALWARE);
  });

  it('returns UNKNOWN for empty string', () => {
    expect(parseVerdict('')).toBe(Verdict.UNKNOWN);
  });

  it('returns UNKNOWN for non-string types', () => {
    expect(parseVerdict(42)).toBe(Verdict.UNKNOWN);
    expect(parseVerdict(null)).toBe(Verdict.UNKNOWN);
    expect(parseVerdict(undefined)).toBe(Verdict.UNKNOWN);
    expect(parseVerdict(true)).toBe(Verdict.UNKNOWN);
    expect(parseVerdict({})).toBe(Verdict.UNKNOWN);
  });

  it('returns UNKNOWN for unrecognized strings', () => {
    expect(parseVerdict('danger')).toBe(Verdict.UNKNOWN);
    expect(parseVerdict('maybe')).toBe(Verdict.UNKNOWN);
  });
});

describe('getVerdictClass', () => {
  it('returns correct CSS class for MALWARE', () => {
    expect(getVerdictClass(Verdict.MALWARE)).toBe('verdict-malware');
  });

  it('returns correct CSS class for SUSPICIOUS', () => {
    expect(getVerdictClass(Verdict.SUSPICIOUS)).toBe('verdict-suspicious');
  });

  it('returns verdict-clean for CLEAN', () => {
    expect(getVerdictClass(Verdict.CLEAN)).toBe('verdict-clean');
  });

  it('returns verdict-clean for UNKNOWN (default)', () => {
    expect(getVerdictClass(Verdict.UNKNOWN)).toBe('verdict-clean');
  });
});

describe('getVerdictLabel', () => {
  it('returns "Malware" for MALWARE', () => {
    expect(getVerdictLabel(Verdict.MALWARE)).toBe('Malware');
  });

  it('returns "Suspicious" for SUSPICIOUS', () => {
    expect(getVerdictLabel(Verdict.SUSPICIOUS)).toBe('Suspicious');
  });

  it('returns "Clean" for CLEAN', () => {
    expect(getVerdictLabel(Verdict.CLEAN)).toBe('Clean');
  });

  it('returns "Unknown" for UNKNOWN', () => {
    expect(getVerdictLabel(Verdict.UNKNOWN)).toBe('Unknown');
  });
});

describe('isThreat', () => {
  it('returns true for MALWARE', () => {
    expect(isThreat(Verdict.MALWARE)).toBe(true);
  });

  it('returns true for SUSPICIOUS', () => {
    expect(isThreat(Verdict.SUSPICIOUS)).toBe(true);
  });

  it('returns false for CLEAN', () => {
    expect(isThreat(Verdict.CLEAN)).toBe(false);
  });

  it('returns false for UNKNOWN', () => {
    expect(isThreat(Verdict.UNKNOWN)).toBe(false);
  });
});
