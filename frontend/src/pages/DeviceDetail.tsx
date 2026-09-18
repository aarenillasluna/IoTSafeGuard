/** Detalle de un dispositivo: runs históricos + CVEs observados. */
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

export function DeviceDetail() {
  const { deviceKey = "" } = useParams<{ deviceKey: string }>();
  const { data, loading, error } = useFetch(
    () => api.getDevice(deviceKey),
    [deviceKey],
  );

  return (
    <div>
      <div style={{ fontSize: ".8rem", marginBottom: ".25rem" }}>
        <Link to="/devices" className="dim">← dispositivos</Link>
      </div>

      {loading && <div className="muted">cargando</div>}
      {error && <div className="error"><strong>error</strong> {error}</div>}

      {data && (
        <>
          <h2 style={{ marginBottom: ".25rem" }}>{data.device_name}</h2>
          <div className="dim mono" style={{ marginBottom: "1.5rem", fontSize: ".75rem" }}>
            {data.device_key}
          </div>

          <dl className="meta" style={{ marginBottom: "1.5rem" }}>
            <dt>vendor</dt><dd>{data.vendor || <span className="dim">—</span>}</dd>
            <dt>modelo</dt><dd>{data.model || <span className="dim">—</span>}</dd>
            <dt>firmware</dt><dd>{data.firmware || <span className="dim">—</span>}</dd>
            <dt>mac</dt><dd>{data.mac || <span className="dim">—</span>}</dd>
            <dt>runs</dt><dd>{data.runs_count}</dd>
            <dt>hallazgos</dt>
            <dd>
              <span className="mono">{data.total_confirmed}</span>
              <span className="dim mono"> /{data.total_findings}</span>
            </dd>
          </dl>

          <h3>
            IPs vistas <span className="dim mono" style={{ fontSize: ".72rem", fontWeight: 400 }}>
              ({data.ips_seen.length})
            </span>
          </h3>
          {data.ips_seen.length === 0 ? (
            <p className="muted">Sin IPs registradas.</p>
          ) : (
            <>
              <p style={{ marginBottom: ".5rem" }}>
                {data.ips_seen.map((ip) => (
                  <span key={ip} className="tag">{ip}</span>
                ))}
              </p>
              <p className="dim" style={{ fontSize: ".78rem", margin: 0 }}>
                La misma IP puede ser dispositivos distintos en redes diferentes.
                Identidad canónica: vendor + modelo + MAC.
              </p>
            </>
          )}

          <h3>Historial de auditorías</h3>
          {data.runs.length === 0 ? (
            <div className="empty">Sin auditorías registradas.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th className="mono">IP</th>
                  <th>Riesgo</th>
                  <th>Hallazgos</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.runs.map((r) => (
                  <tr key={r.report_id}>
                    <td className="mono">{formatTimestamp(r.timestamp)}</td>
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
                    <td>
                      <Link to={`/reports/${r.report_id}`}>reporte</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h3>CVEs observados</h3>
          {data.cves_seen.length === 0 ? (
            <div className="empty">Sin CVEs registrados todavía.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severidad</th>
                  <th>Estado</th>
                  <th>Último run</th>
                </tr>
              </thead>
              <tbody>
                {data.cves_seen.map((c) => (
                  <tr key={c.cve_id}>
                    <td className="mono">
                      <Link to={`/cves/${c.cve_id}`}>{c.cve_id}</Link>
                    </td>
                    <td>
                      <SeverityBadge value={c.severity} />
                    </td>
                    <td>
                      {c.confirmed_occurrences > 0 ? (
                        <>
                          <span className="sev confirmed">
                            {c.confirmed_occurrences}/{c.occurrences} confirmado
                            {c.confirmed_occurrences > 1 ? "s" : ""}
                          </span>
                        </>
                      ) : (
                        <span className="sev dismissed">
                          0/{c.occurrences} descartado
                        </span>
                      )}
                    </td>
                    <td className="mono dim" style={{ fontSize: ".78rem" }}>
                      {formatTimestamp(c.last_run)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
