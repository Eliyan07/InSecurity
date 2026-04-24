/** Network security types matching Rust backend serde(rename_all = "camelCase") */


export interface NetworkEvent {
  id: number;
  pid: number;
  processName: string;
  processPath: string | null;
  remoteIp: string;
  remotePort: number;
  protocol: string;
  eventType: string;
  reason: string | null;
  createdAt: number;
}

export interface FirewallRule {
  id: number;
  ruleName: string;
  executablePath: string;
  direction: string;
  action: string;
  reason: string | null;
  autoCreated: boolean;
  enabled: boolean;
  createdAt: number;
}

export interface ActiveConnection {
  pid: number;
  processName: string;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  state: string;
  protocol: string;
  suspicious: boolean;
  threatName: string | null;
}

export interface NetworkThreatEvent {
  pid: number;
  processName: string;
  processPath: string;
  remoteIp: string;
  remotePort: number;
  threatName: string;
  protocol: string;
}
