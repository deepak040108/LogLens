import type { Job, Rule, ThreatEvent } from "../types";

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json();
}

export async function uploadLogFile(file: File): Promise<{ job_id: string; status: string }> {
  const form = new FormData();
  form.append("logfile", file);
  const res = await fetch("/api/upload", { method: "POST", body: form });
  return handle(res);
}

export async function loadDemoLog(): Promise<{ job_id: string; status: string }> {
  const res = await fetch("/api/demo", { method: "POST" });
  return handle(res);
}

export async function getJob(jobId: string): Promise<Job> {
  const res = await fetch(`/api/jobs/${jobId}`);
  return handle(res);
}

export interface ThreatFilters {
  severity?: string;
  attack_type?: string;
  ip?: string;
}

export async function getThreats(jobId: string, filters: ThreatFilters = {}): Promise<{ events: ThreatEvent[]; count: number }> {
  const params = new URLSearchParams();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.attack_type) params.set("attack_type", filters.attack_type);
  if (filters.ip) params.set("ip", filters.ip);
  const qs = params.toString();
  const res = await fetch(`/api/threats/${jobId}${qs ? `?${qs}` : ""}`);
  return handle(res);
}

export async function getRules(): Promise<{ rules: Rule[] }> {
  const res = await fetch("/api/rules");
  return handle(res);
}

export async function setRuleStatus(rule: string, status: "enabled" | "disabled"): Promise<void> {
  const res = await fetch(`/api/rules/${rule}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  await handle(res);
}

export function reportUrl(jobId: string, format: "json" | "csv" | "pdf") {
  return `/api/reports/${jobId}?format=${format}`;
}

export async function checkHealth(): Promise<{ ok: boolean; geoipAvailable: boolean; geoipStatus: string }> {
  const res = await fetch("/api/health");
  return handle(res);
}

export async function getFindings(
  jobId: string,
  params: { page?: number; limit?: number; severity?: string; attack_type?: string; ip?: string } = {}
): Promise<{ events: ThreatEvent[]; count: number }> {
  const qs = new URLSearchParams();
  if (params.page) qs.set("page", String(params.page));
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.severity) qs.set("severity", params.severity);
  if (params.attack_type) qs.set("attack_type", params.attack_type);
  if (params.ip) qs.set("ip", params.ip);
  const query = qs.toString();
  const res = await fetch(`/api/findings/${jobId}${query ? `?${query}` : ""}`);
  return handle(res);
}

export interface Settings {
  bruteForceThreshold: number;
  bruteForceWindowSeconds: number;
  maxUploadBytes: number;
  allowedExtensions: string[];
  chunkSize: number;
  jobQueueBackend: string;
  geoipAvailable: boolean;
  geoipCityAvailable: boolean;
  geoipAsnAvailable: boolean;
  geoipStatus: string;
  geoipDbPath: string;
}

export async function getSettings(): Promise<Settings> {
  const res = await fetch("/api/settings");
  return handle(res);
}
