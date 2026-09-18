/** Buscador de CVEs observados en al menos un dispositivo. */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export function CvesList() {
  const { data, loading, error } = useFetch(() => api.listCves(), []);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<SeverityFilter>("ALL");
  const [onlyConfirmed, setOnlyConfirmed] = useState(false);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.filter((c) => {
      if (sev !== "ALL" && (c.severity || "").toUpperCase() !== sev) return false;
      if (onlyConfirmed && c.confirmed_occurrences === 0) return false;
      if (!q) return true;
      const hay = [
        c.cve_id,
        c.description,
        ...(c.devices_seen || []),
        ...(c.kb_vendors_tested || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [data, query, sev, onlyConfirmed]);

  return (
    <div>
      <div className="headline">
        <h2>CVEs</h2>
        <span className="tag">solo los vistos al menos una vez en algún run</span>
      </div>

      <div className="row" style={{ marginBottom: "1.25rem", alignItems: "stretch" }}>
        <div style={{ flex: "1 1 280px", maxWidth: 480 }}>
          <input
            type="search"
            placeholder="CVE-ID, descripción, dispositivo…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div style={{ width: 170 }}>
          <select value={sev} onChange={(e) => setSev(e.target.value as SeverityFilter)}>
            <option value="ALL">cualquier severidad</option>
            <option value="CRITICAL">critical</option>
            <option value="HIGH">high</option>
            <option value="MEDIUM">medium</option>
            <option value="LOW">low</option>
            <option value="INFO">info</option>
          </select>
        </div>
        <label className="row" style={{ cursor: "pointer", gap: ".4rem", fontSize: ".85rem" }}>
          <input
            type="checkbox"
            checked={onlyConfirmed}
            onChange={(e) => setOnlyConfirmed(e.target.checked)}
          />
          solo confirmados
        </label>
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
          {data.length === 0 ? "Sin CVEs registrados." : "Ningún CVE para esos filtros."}
        </div>
      )}

      {filtered.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Severidad</th>
              <th>Score</th>
              <th>Confirmaciones</th>
              <th>Devices</th>
              <th>Última vez</th>
              <th>Descripción</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => {
              const c_ok = c.confirmed_occurrences;
              const c_total = c.total_occurrences;
              return (
                <tr key={c.cve_id}>
                  <td className="mono">
                    <Link to={`/cves/${c.cve_id}`}>{c.cve_id}</Link>
                  </td>
                  <td>
                    <SeverityBadge value={c.severity} />
                  </td>
                  <td className="mono">{c.score != null ? c.score.toFixed(1) : "—"}</td>
                  <td>
                    {c_total === 0 ? (
                      <span className="dim">sin pruebas</span>
                    ) : (
                      <>
                        <span className="mono">{c_ok}</span>
                        <span className="dim mono"> /{c_total}</span>
                      </>
                    )}
                  </td>
                  <td className="mono">{c.devices_seen.length}</td>
                  <td className="mono dim" style={{ fontSize: ".78rem" }}>
                    {formatTimestamp(c.last_seen)}
                  </td>
                  <td
                    className="dim"
                    style={{
                      maxWidth: 380,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={c.description || ""}
                  >
                    {c.description || "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
