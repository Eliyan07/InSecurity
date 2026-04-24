
export interface QuarantineEntry {
  id: number;
  fileHash: string;
  originalPath: string;
  quarantinePath: string;
  verdict: string;
  threatLevel: string;
  reason: string;
  quarantinedAt: number;
  restoredAt?: number;
  permanentlyDeleted: boolean;
  fileSize: number;
  fileType: string;
}

export interface QuarantineStats {
  totalItems: number;
  highThreatItems: number;
  mediumThreatItems: number;
  lowThreatItems: number;
  totalStorageMb: number;
}
