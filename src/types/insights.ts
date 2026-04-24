export type TrustLevel =
  | 'none'
  | 'unknown'
  | 'untrusted'
  | 'publisher-allowlist'
  | 'publisher-match'
  | 'ca'
  | 'self-signed'
  | 'invalid';

/** Structural classification - NOT a malware confidence level.
 *  Describes *why* an item is surfaced, not whether it's malicious. */
export type PostureStatus = 'flagged' | 'unusual' | 'unverified' | 'verified' | 'unknown';

export interface StartupEntry {
  name: string;
  command: string;
  location: string;
  executablePath?: string;
  persistenceType: string;
  isSigned: boolean;
  isTrusted: boolean;
  trustLevel?: TrustLevel;
  signerName?: string;
  observations: string[];
  status: PostureStatus;
  priorVerdict?: string;
}

export interface PersistenceItem {
  name: string;
  itemType: string;
  command: string;
  executablePath?: string;
  isSigned: boolean;
  isTrusted: boolean;
  trustLevel?: TrustLevel;
  signerName?: string;
  observations: string[];
  status: PostureStatus;
  priorVerdict?: string;
  details?: string;
}

/** Persistence context for a specific file - returned by get_persistence_for_file */
export interface FilePersistenceContext {
  filePath: string;
  startupEntries: StartupEntry[];
  persistenceItems: PersistenceItem[];
  isSigned: boolean;
  isTrusted: boolean;
  signerName?: string;
  observations: string[];
}
