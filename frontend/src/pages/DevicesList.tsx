/** Listado de dispositivos agrupados por identidad canónica (vendor|model|MAC). */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

export function DevicesList() {
  const { data, loading, error } = useFetch(() => api.listDevices(), []);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    if (!q) return data;
    return data.filter((d) => {
      const hay = [
        d.device_name,
        d.vendor,
        d.model,
        d.mac,
        d.firmware,
        ...(d.ips_seen || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [data, query]);

  return (
    <div>
      <div className="headline">
        <h2>Dispositivos</h2>
        <span className="tag">agrupados por vendor + modelo + MAC, nunca por IP</span>
      </div>

      <div className="row" style={{ marginBottom: "1.25rem" }}>
        <div style={{ flex: "1 1 320px", maxWidth: 480 }}>
          <input
            type="search"
            placeholder="vendor, modelo, IP, MAC…"
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
          {data.length === 0 ? (
            <>Aún ningún dispositivo. Lánzate desde <Link to="/launch">auditar</Link>.</>
          ) : (
            "Sin coincidencias para esa búsqueda."
          )}
        </div>
      )}

      {filtered.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Dispositivo</th>
              <th>Identidad</th>
              <th className="mono">MAC</th>
              <th>IPs vistas</th>
              <th>Runs</th>
              <th>Hallazgos</th>
              <th>Último riesgo</th>
              <th>Visto</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((d) => (
              <tr key={d.device_key}>
                <td>
                  <Link to={`/devices/${encodeURIComponent(d.device_key)}`}>
                    {d.device_name}
                  </Link>
                  {d.firmware && (
                    <div className="dim mono" style={{ fontSize: ".72rem" }}>
                      fw {d.firmware}
                    </div>
                  )}
                </td>
                <td>
                  <div className="mono">{d.vendor || <span className="dim">—</span>}</div>
                  <div className="dim mono" style={{ fontSize: ".72rem" }}>
                    {d.model || ""}
                  </div>
                </td>
                <td className="mono">{d.mac || <span className="dim">—</span>}</td>
                <td>
                  {d.ips_seen.length === 0 ? (
                    <span className="dim">—</span>
                  ) : (
                    d.ips_seen.map((ip) => <span key={ip} className="tag">{ip}</span>)
                  )}
                </td>
                <td className="mono">{d.runs_count}</td>
                <td>
                  <span className="mono">{d.total_confirmed}</span>
                  <span className="dim mono"> /{d.total_findings}</span>
                </td>
                <td>
                  <SeverityBadge value={d.last_risk_label} />
                  {d.last_risk_score != null && (
                    <span className="dim mono"> {d.last_risk_score.toFixed(1)}</span>
                  )}
                </td>
                <td className="mono dim" style={{ fontSize: ".78rem" }}>
                  {formatTimestamp(d.last_seen)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
