/** Detalle de un CVE: metadatos + historial KB + todas las ocurrencias. */
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { SeverityBadge, ConfirmedBadge } from "../components/SeverityBadge";
import { formatTimestamp } from "../lib/format";

export function CveDetail() {
  const { cveId = "" } = useParams<{ cveId: string }>();
  const { data, loading, error } = useFetch(() => api.getCve(cveId), [cveId]);

  return (
    <div>
      <div style={{ fontSize: ".8rem", marginBottom: ".25rem" }}>
        <Link to="/cves" className="dim">← cves</Link>
      </div>

      {loading && <div className="muted">cargando</div>}
      {error && <div className="error"><strong>error</strong> {error}</div>}

      {data && (
        <>
          <div className="row spread">
            <h2 style={{ margin: 0 }} className="mono">{data.cve_id}</h2>
            <div className="row">
              <SeverityBadge value={data.severity} />
              {data.score != null && (
                <span className="tag mono">CVSS {data.score.toFixed(1)}</span>
              )}
            </div>
          </div>

          {data.description && (
            <p className="muted" style={{ margin: ".75rem 0 1.5rem", maxWidth: 760 }}>
              {data.description}
            </p>
          )}

          <div className="numbers">
            <div className="n">
              <span className="value">{data.confirmed_occurrences}</span>
              <span className="label">ocurrencias confirmadas</span>
            </div>
            <div className="n">
              <span className="value">{data.total_occurrences}</span>
              <span className="label">total ocurrencias</span>
            </div>
            <div className="n">
              <span className="value">{data.kb_history.tested_n_times}</span>
              <span className="label">probado n veces (KB)</span>
            </div>
            <div className="n">
              <span className="value">{data.kb_history.confirmed_count}</span>
              <span className="label">confirmados (KB)</span>
            </div>
          </div>

          <h3>Historial KB</h3>
          <dl className="meta">
            <dt>primera prueba</dt>
            <dd>{formatTimestamp(data.kb_history.first_test)}</dd>
            <dt>última prueba</dt>
            <dd>{formatTimestamp(data.kb_history.last_test)}</dd>
            <dt>vendors probados</dt>
            <dd>
              {data.kb_history.vendors_tested.length === 0 ? (
                <span className="dim">—</span>
              ) : (
                data.kb_history.vendors_tested.map((v) => (
                  <span key={v} className="tag">{v}</span>
                ))
              )}
            </dd>
          </dl>

          <h3>
            Ocurrencias{" "}
            <span className="dim mono" style={{ fontSize: ".72rem", fontWeight: 400 }}>
              ({data.occurrences.length})
            </span>
          </h3>
          {data.occurrences.length === 0 ? (
            <div className="empty">
              Este CVE aún no se ha probado contra ningún dispositivo.
            </div>
          ) : (
            <div className="stack">
              {data.occurrences.map((o, i) => (
                <OccurrenceCard key={`${o.report_id}-${i}`} occurrence={o} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function OccurrenceCard({
  occurrence: o,
}: {
  occurrence: import("../types/api").CveOccurrence;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card">
      <div className="row spread">
        <div className="stack" style={{ gap: ".25rem" }}>
          <div className="row" style={{ gap: ".75rem" }}>
            <ConfirmedBadge confirmed={o.confirmed} />
            <SeverityBadge value={o.severity} />
            <strong style={{ fontWeight: 500 }}>{o.title || "(sin título)"}</strong>
          </div>
          <div className="dim mono" style={{ fontSize: ".78rem" }}>
            {formatTimestamp(o.timestamp)} ·{" "}
            <Link to={`/devices/${encodeURIComponent(o.device_key)}`}>
              {o.device_name}
            </Link>{" "}
            · {o.target_ip || "—"}
          </div>
        </div>
        <div className="row">
          <Link to={`/reports/${o.report_id}`}>reporte</Link>
          <button
            type="button"
            className="secondary"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "ocultar" : "detalle"}
          </button>
        </div>
      </div>

      {open && (
        <div style={{ marginTop: "1rem" }} className="stack">
          {(o.repro_cmd ?? o.executed_cmd) && (
            <div>
              <div className="dim mono" style={{ fontSize: ".72rem", marginBottom: ".25rem" }}>
                comando de reproducción
              </div>
              <pre className="terminal" style={{ maxHeight: 120 }}>
                {o.repro_cmd ?? o.executed_cmd}
              </pre>
            </div>
          )}
          {o.interpretation && (
            <div>
              <div className="dim mono" style={{ fontSize: ".72rem", marginBottom: ".25rem" }}>
                interpretación
              </div>
              <div style={{ background: "var(--surface-2)", padding: ".75rem 1rem" }}>
                {o.interpretation}
              </div>
            </div>
          )}
          {o.raw_output && (
            <div>
              <div className="dim mono" style={{ fontSize: ".72rem", marginBottom: ".25rem" }}>
                salida cruda
              </div>
              <pre className="terminal">{o.raw_output}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
