/** Tipos espejados de api/services/aggregator.py — mantén sincronizado. */

export interface SeverityCounts {
  CRITICAL?: number;
  HIGH?: number;
  MEDIUM?: number;
  LOW?: number;
  INFO?: number;
}

export interface ReportSummary {
  id: string;
  timestamp: string | null;
  target_ip: string | null;
  vendor: string | null;
  model: string | null;
  firmware: string | null;
  mac: string | null;
  device_key: string;
  device_name: string;
  risk_score: number | null;
  risk_label: string | null;
  confirmed_count: number;
  total_findings: number;
  severity_counts: SeverityCounts;
  confirmed_severity_counts: SeverityCounts;
}

export interface DeviceSummary {
  device_key: string;
  device_name: string;
  vendor: string | null;
  model: string | null;
  firmware: string | null;
  mac: string | null;
  ips_seen: string[];
  runs_count: number;
  first_seen: string | null;
  last_seen: string | null;
  total_confirmed: number;
  total_findings: number;
  last_risk_label: string | null;
  last_risk_score: number | null;
}

export interface DeviceCveSeen {
  cve_id: string;
  severity: string | null;
  occurrences: number;
  confirmed_occurrences: number;
  last_run: string;
}

export interface DeviceRun {
  report_id: string;
  timestamp: string | null;
  target_ip: string | null;
  risk_score: number | null;
  risk_label: string | null;
  confirmed_count: number;
  total_findings: number;
}

export interface DeviceDetail extends DeviceSummary {
  runs: DeviceRun[];
  cves_seen: DeviceCveSeen[];
}

export interface CveSummary {
  cve_id: string;
  severity: string | null;
  score: number | null;
  description: string | null;
  total_occurrences: number;
  confirmed_occurrences: number;
  devices_seen: string[];
  last_seen: string | null;
  kb_tested_n_times?: number;
  kb_confirmed_count?: number;
  kb_vendors_tested?: string[];
}

export interface CveOccurrence {
  report_id: string;
  timestamp: string | null;
  device_key: string;
  device_name: string;
  target_ip: string | null;
  confirmed: boolean;
  severity: string | null;
  title: string | null;
  /** Comando que REPRODUCE el hallazgo (puede ser el nombre de la sonda que lo
   *  emitió). Se llamaba `executed_cmd`, nombre que afirmaba una ejecución no
   *  garantizada; los informes antiguos aún lo traen con el nombre anterior. */
  repro_cmd: string | null;
  /** @deprecated informes generados antes del renombrado a `repro_cmd`. */
  executed_cmd?: string | null;
  raw_output: string;
  interpretation: string;
}

export interface CveDetail {
  cve_id: string;
  severity: string | null;
  score: number | null;
  description: string | null;
  total_occurrences: number;
  confirmed_occurrences: number;
  occurrences: CveOccurrence[];
  kb_history: {
    tested_n_times: number;
    confirmed_count: number;
    first_test: string | null;
    last_test: string | null;
    vendors_tested: string[];
  };
}

export interface GlobalStats {
  runs_total: number;
  devices_total: number;
  cves_total: number;
  cves_confirmed_at_least_once: number;
  vendors_known: string[];
  last_5_runs: ReportSummary[];
}

/** Cómo se reparte una tanda entre los aparatos seleccionados.
 *  - `secuencial`: una auditoría a la vez, sea cual sea el objetivo. Es el modo
 *    con el que se midieron las cifras de varianza de la memoria.
 *  - `por_dispositivo`: un run de cada aparato a la vez; las réplicas de cada
 *    uno siguen en orden estricto. Nunca dos runs contra el mismo aparato.
 */
export type ModoTanda = "secuencial" | "por_dispositivo";

export interface AuditSummary {
  audit_id: string;
  target_ip: string;
  model: string | null;
  extra_args: string[];
  /** true = el run se lanzó con `--no-policy` (modo investigación, shell directo). */
  policy_disabled: boolean;
  started_at: number;
  finished_at: number | null;
  exit_code: number | null;
  is_running: boolean;
  /** En cola, esperando turno: la ejecución es de una en una. */
  is_queued: boolean;
  /** 0 = ejecutándose; >0 = puesto en la cola de SU carril. */
  queue_position: number;
  /** Carril en el que corre; con el modo por dispositivo hay uno por IP. */
  lane?: string;
  was_stopped: boolean;
  /** Réplica i de N sobre el mismo target (cadena secuencial); 1/1 = run único. */
  replica_index: number;
  replica_total: number;
  log_lines: number;
  listeners: number;
}

export interface ScannedHost {
  ip: string;
  mac: string | null;
  vendor: string | null;
  hostname: string | null;
}

export interface ScanResult {
  cidr: string;
  hosts: ScannedHost[];
  host_count: number;
}

export type StreamMessage =
  | { type: "line"; data: string; n: number; replay?: boolean }
  | { type: "done"; exit_code: number; elapsed_seconds: number; total_lines: number; replay?: boolean }
  | { type: "stopping"; data: string }
  | { type: "error"; data: string };
