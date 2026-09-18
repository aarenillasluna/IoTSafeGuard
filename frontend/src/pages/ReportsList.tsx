/** Listado de todos los reportes de auditoría. */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

export function ReportsList() {
  const { data, loading, error } = useFetch(() => api.listReports(), []);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    if (!q) return data;
    return data.filter((r) => {
      const hay = [r.id, r.device_name, r.vendor, r.model, r.firmware, r.target_ip, r.mac]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [data, query]);

  return (
    <div>
      <div className="headline">
        <h2>Reportes</h2>
        <span className="tag">reports/audit_report_*.{`{json,md,html,sarif}`}</span>
      </div>

      <div className="row" style={{ marginBottom: "1.25rem" }}>
        <div style={{ flex: "1 1 320px", maxWidth: 480 }}>
          <input
            type="search"
            placeholder="dispositivo, IP, ID…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        {data && (
          <span className="dim mono">
            {filtered.length}{filtered.length !== data.length ? ` / ${data.length}` : ""}
          </span>
        )}
      </div>

      {loading && <div className="muted">cargando</div>}
      {error && <div className="error"><strong>error</strong> {error}</div>}

      {data && filtered.length === 0 && (
        <div className="empty">
          {data.length === 0 ? "Sin reportes todavía." : "Sin coincidencias."}
        </div>
      )}

      {filtered.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Cuándo</th>
              <th>Dispositivo</th>
              <th className="mono">IP</th>
              <th>Riesgo</th>
              <th>Hallazgos</th>
              <th>ID</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="mono">{formatTimestamp(r.timestamp)}</td>
                <td>
                  <Link to={`/devices/${encodeURIComponent(r.device_key)}`}>
                    {r.device_name}
                  </Link>
                </td>
                <td className="mono">{r.target_ip || "—"}</td>
                <td>
                  <SeverityBadge value={r.risk_label} />
                  {r.risk_score != null && (
                    <span className="dim mono"> {r.risk_score.toFixed(1)}</span>
                  )}
                </td>
                <td>
                  <span className="mono">{r.confirmed_count}</span>
                  <span className="dim mono"> /{r.total_findings}</span>
                </td>
                <td className="mono dim" style={{ fontSize: ".72rem" }}>
                  {r.id.replace(/^audit_report_/, "")}
                </td>
                <td>
                  <Link to={`/reports/${r.id}`}>abrir</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
