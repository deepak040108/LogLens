// Shared types mirroring the backend's actual JSON shapes (routes/*.py).
// Kept as one file rather than scattered per-component so a backend
// field rename is a one-place fix on the frontend.

export type Severity = "critical" | "high" | "medium" | "low";
export type JobStatus = "queued" | "processing" | "completed" | "failed";

export interface JobProgress {
  totalLines: number;
  parsedLines: number;
  malformedLines: number;
  percent: number;
}

export interface SeverityBreakdownEntry {
  severity: Severity;
  count: number;
  percentage: number;
}

export interface TimelineEntry {
  hour: string; // "YYYY-MM-DDTHH"
  count: number;
}

export interface AttackTypeEntry {
  attack_type: string;
  count: number;
}

export interface AttackerRow {
  ip: string;
  count: number;
  country: string;
  countryCode: string | null;
  geoAvailable: boolean;
  city: string | null;
  region: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  organization: string | null;
  topAttack: string | null;
  severity: Severity;
  firstSeen: string | null;
  lastSeen: string | null;
  attackHistory: { attack_type: string; count: number }[];
}

export interface CountryRow {
  country: string;
  countryCode: string | null;
  attackCount: number;
  uniqueIps: number;
}

export interface ThreatEvent {
  ip: string;
  timestamp: string | null;
  method: string;
  path: string;
  status: number;
  userAgent: string | null;
  attack_type: string;
  severity: Severity;
  matched_signature: string;
  reason: string;
  all_matches: { attack_type: string; severity: Severity; matched_signature: string }[];
}

export interface JobSummary {
  totalLines: number;
  totalRequests: number;
  malformedLines: number;
  totalAttacks: number;
  uniqueAttackerIps: number;
  statusCounts: Record<string, number>;
  severityBreakdown: SeverityBreakdownEntry[];
  timeline: TimelineEntry[];
  byType: AttackTypeEntry[];
  byCountry: CountryRow[];
  geoipAvailable: boolean;
  topAttackers: AttackerRow[];
  recentFindings: ThreatEvent[];
}

export interface Job {
  job_id: string;
  status: JobStatus;
  total_lines: number;
  processed_lines: number;
  malformed_lines: number;
  progress: number;
  error: string | null;
  summary: JobSummary | null;
}

export interface Rule {
  rule: string;
  attackType: string;
  severity: Severity;
  description: string;
  patternCount: number;
  status: "enabled" | "disabled";
}

export interface ThreatScore {
  score: number;
  level: string;
  contributors: Array<{ factor: string; points: number; detail: string }>;
  summary: string;
}

export interface CorrelationFinding {
  type: string;
  description: string;
  ips: string[];
  timeWindow: string;
  severity: string;
}

export interface EnhancedAttacker {
  ip: string;
  count: number;
  country: string;
  countryCode: string | null;
  geoAvailable: boolean;
  city: string | null;
  region: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  organization: string | null;
  topAttack: string | null;
  severity: Severity;
  firstSeen: string | null;
  lastSeen: string | null;
  attackHistory: { attack_type: string; count: number }[];
  threatScore?: ThreatScore;
  targetedEndpoints?: Array<{ path: string; count: number }>;
}

export interface EnhancedFinding {
  ip: string;
  timestamp: string | null;
  method: string;
  path: string;
  status: number;
  userAgent: string | null;
  attack_type: string;
  severity: Severity;
  matched_signature: string;
  reason: string;
  all_matches: { attack_type: string; severity: Severity; matched_signature: string }[];
  rule_id?: string;
  confidence?: string;
  recommendation?: string;
}
