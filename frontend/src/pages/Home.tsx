/** Home: bienvenida concisa, cifras inline, últimas auditorías. */
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

export function Home() {
  const { data, loading, error } = useFetch(() => api.globalStats(), []);

  return (
    <div>
      <div className="headline">
        <h2>Resumen</h2>
        <span className="tag">/api/stats</span>
      </div>

      {loading && <div className="muted">cargando</div>}
      {error && (
        <div className="error">
          <strong>error</strong> {error}
        </div>
      )}

      {data && (
        <>
          <div className="numbers">
            <div className="n">
              <span className="value">{data.runs_total}</span>
              <span className="label">auditorías</span>
            </div>
            <div className="n">
              <span className="value">{data.devices_total}</span>
              <span className="label">dispositivos únicos</span>
            </div>
            <div className="n">
              <span className="value">{data.cves_total}</span>
              <span className="label">cves catalogados</span>
            </div>
            <div className="n">
              <span className="value">{data.cves_confirmed_at_least_once}</span>
              <span className="label">cves confirmados</span>
            </div>
          </div>

          <h3>Vendors</h3>
          {data.vendors_known.length === 0 ? (
            <p className="muted">Aún ningún vendor en la KB.</p>
          ) : (
            <p>
              {data.vendors_known.map((v, i) => (
                <span key={v}>
                  <span className="mono">{v}</span>
                  {i < data.vendors_known.length - 1 ? <span className="dim"> · </span> : null}
                </span>
              ))}
            </p>
          )}

          <h3>Últimas auditorías</h3>
          {data.last_5_runs.length === 0 ? (
            <div className="empty">
              Sin auditorías todavía. <Link to="/launch">Lanzar la primera</Link>.
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Dispositivo</th>
                  <th className="mono">IP</th>
                  <th>Riesgo</th>
                  <th>Hallazgos</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.last_5_runs.map((r) => (
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
                    <td>
                      <Link to={`/reports/${r.id}`}>reporte</Link>
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
