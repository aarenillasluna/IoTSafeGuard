/** Detalle de auditoría: metadatos + terminal WS en vivo. */
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../components/useFetch";
import { useNow } from "../components/useNow";
import { LiveTerminal } from "../components/LiveTerminal";
import { formatEpoch, formatDuration, formatElapsedClock } from "../lib/format";

export function AuditStream() {
  const { auditId = "" } = useParams<{ auditId: string }>();
  const { data, loading, error, refresh } = useFetch(
    () => api.getAudit(auditId),
    [auditId],
  );
  const [finalExit, setFinalExit] = useState<number | null>(null);
  const [stopping, setStopping] = useState(false);
  // Reloj de 1 s mientras corre: la duración "(en curso)" avanza sola.
  const now = useNow(1000, !!data?.is_running && finalExit == null);

  async function handleStop() {
    if (!auditId || stopping) return;
    setStopping(true);
    try {
      await api.stopAudit(auditId);
    } catch {
      /* el WS reflejará el cierre igualmente */
    } finally {
      setStopping(false);
      refresh();
    }
  }

  return (
    <div>
      <div className="row spread" style={{ marginBottom: "1rem" }}>
        <div>
          <div style={{ fontSize: ".8rem", marginBottom: ".25rem" }}>
            <Link to="/launch" className="dim">← auditar</Link>
          </div>
          <h2 style={{ margin: 0 }}>Auditoría en vivo</h2>
          <div className="dim mono" style={{ fontSize: ".75rem" }}>{auditId}</div>
        </div>
        <div className="row" style={{ gap: ".5rem" }}>
          {data?.is_running && (
            <button
              type="button"
              onClick={handleStop}
              disabled={stopping}
              style={{
                background: "#b3261e", color: "#fff", border: "none",
                padding: ".45rem .9rem", borderRadius: ".4rem",
                cursor: stopping ? "default" : "pointer", opacity: stopping ? 0.7 : 1,
              }}
            >
              {stopping ? "deteniendo…" : "⏹ detener"}
            </button>
          )}
          <button type="button" className="secondary" onClick={refresh}>
            refrescar
          </button>
        </div>
      </div>

      {loading && <div className="muted">cargando</div>}
      {error && <div className="error"><strong>error</strong> {error}</div>}

      {data && (
        <>
          <dl className="meta" style={{ marginBottom: "1.5rem" }}>
            <dt>target</dt><dd>{data.target_ip}</dd>
            <dt>modelo</dt><dd>{data.model || <span className="dim">(default)</span>}</dd>
            <dt>inicio</dt><dd>{formatEpoch(data.started_at)}</dd>
            <dt>duración</dt>
            <dd>
              {data.finished_at != null
                ? formatDuration(data.finished_at - data.started_at)
                : formatElapsedClock(now / 1000 - data.started_at) + " (en curso)"}
            </dd>
            <dt>estado</dt>
            <dd>
              {data.is_running
                ? <span className="status live">en curso</span>
                : data.was_stopped
                  ? <span className="status error">detenida</span>
                  : data.exit_code === 0
                    ? <span className="status done">ok</span>
                    : <span className="status error">exit {data.exit_code ?? "?"}</span>}
            </dd>
            <dt>líneas</dt><dd>{data.log_lines}</dd>
            {data.extra_args.length > 0 && (
              <>
                <dt>args</dt>
                <dd className="mono">{data.extra_args.join(" ")}</dd>
              </>
            )}
          </dl>

          <h3 style={{ marginTop: 0 }}>Salida del agente</h3>
          <LiveTerminal
            url={api.streamUrl(auditId)}
            onDone={(code) => {
              setFinalExit(code);
              refresh();
            }}
            maxHeightVh={65}
          />

          {finalExit != null && (
            <div className="row spread" style={{ marginTop: "1rem" }}>
              <div className="muted">
                Auditoría finalizada con código{" "}
                <span className={`status ${finalExit === 0 ? "done" : "error"}`}>
                  {finalExit}
                </span>
              </div>
              <Link to="/reports">ver reportes →</Link>
            </div>
          )}

          <div style={{ marginTop: "1rem" }}>
            <a
              href={api.auditLogUrl(auditId)}
              target="_blank"
              rel="noreferrer"
              className="tag"
              style={{ padding: ".3rem .6rem" }}
            >
              descargar log completo
            </a>
          </div>
        </>
      )}
    </div>
  );
}
