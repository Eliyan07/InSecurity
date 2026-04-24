
export type ExclusionType = 'path' | 'folder' | 'extension' | 'pattern';

export interface Exclusion {
  id: number;
  exclusion_type: ExclusionType;
  pattern: string;
  reason: string | null;
  enabled: boolean;
  created_at: number;
  updated_at: number;
}

export interface ExclusionInput {
  exclusion_type: ExclusionType;
  pattern: string;
  reason?: string;
}

export interface ExclusionUpdate {
  id: number;
  exclusion_type?: ExclusionType;
  pattern?: string;
  reason?: string;
  enabled?: boolean;
}
