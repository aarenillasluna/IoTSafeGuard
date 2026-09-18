/** Cliente API tipado. Todas las requests van a /api/* via el proxy de Vite. */
import type {
  AuditSummary,
  CveDetail,
  CveSummary,
  DeviceDetail,
  DeviceSummary,
  GlobalStats,
  ModoTanda,
  ReportSummary,
  ScanResult,
} from "../types/api";

async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} → HTTP ${r.status}`);
  return r.json() as Promise<T>;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${path} → HTTP ${r.status}: ${text}`);
  }
  return r.json() as Promise<T>;
}

export const api = {
  globalStats: () => getJSON<GlobalStats>("/api/reports/stats"),

  listReports: () =>
    getJSON<{ reports: ReportSummary[] }>("/api/reports").then((r) => r.reports),
  getReport: (id: string) => getJSON<Record<string, unknown>>(`/api/reports/${id}`),
  reportHtmlUrl: (id: string) => `/api/reports/${id}/html`,
  reportSarifUrl: (id: string) => `/api/reports/${id}/sarif`,

  listDevices: () =>
    getJSON<{ devices: DeviceSummary[] }>("/api/devices").then((r) => r.devices),
  getDevice: (key: string) =>
    getJSON<DeviceDetail>(`/api/devices/${encodeURIComponent(key)}`),

  listCves: () =>
    getJSON<{ cves: CveSummary[] }>("/api/cves").then((r) => r.cves),
  getCve: (cve_id: string) => getJSON<CveDetail>(`/api/cves/${cve_id}`),

  listAudits: () =>
    getJSON<{ audits: AuditSummary[] }>("/api/audits").then((r) => r.audits),
  getAudit: (id: string) => getJSON<AuditSummary>(`/api/audits/${id}`),
  auditLogUrl: (id: string) => `/api/audits/${id}/log`,
  startAudit: (payload: {
    target_ip: string;
    model?: string;
    disable_policy?: boolean;
    extra_args?: string[];
  }) => postJSON<AuditSummary>("/api/audits", payload),
  startAuditsBatch: (payload: {
    target_ips: string[];
    runs_per_target?: number;
    model?: string;
    disable_policy?: boolean;
    /** "secuencial" (una a la vez) | "por_dispositivo" (una por aparato a la vez) */
    modo?: ModoTanda;
    extra_args?: string[];
  }) =>
    postJSON<{ audits: AuditSummary[] }>("/api/audits/batch", payload).then(
      (r) => r.audits,
    ),
  stopAudit: (id: string) => postJSON<AuditSummary>(`/api/audits/${id}/stop`, {}),
  streamUrl: (audit_id: string) => {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${window.location.host}/api/audits/${audit_id}/stream`;
  },

  scanSubnet: (cidr: string, timeout_seconds = 60) =>
    postJSON<ScanResult>("/api/scan", { cidr, timeout_seconds }),
};
