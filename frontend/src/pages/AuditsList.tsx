/** Ejecuciones: estado vivo de todas las auditorías (en curso e históricas
 *  de esta sesión del backend).
 *  - Polling de la lista cada 3 s + reloj local de 1 s para las duraciones.
 *  - Cada fila se puede desplegar para ver su terminal en vivo (WS) sin salir
 *    de la página; "abrir" navega a la vista completa /audits/:id.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { LiveTerminal } from "../components/LiveTerminal";
import { useNow } from "../components/useNow";
import { formatEpoch, formatDuration, formatElapsedClock } from "../lib/format";
import type { AuditSummary } from "../types/api";

const POLL_MS = 3000;

function statusChip(a: AuditSummary) {
  if (a.is_running) return <span className="status live">en curso</span>;
  if (a.was_stopped) return <span className="status error">detenida</span>;
  // Con la cola global una auditoría recién lanzada puede pasar minutos
  // esperando turno; mostrarla como «en marcha» hacía pensar que se colgó.
  if (a.is_queued)
    return (
      <span className="status" title="Las auditorías se ejecutan de una en una">
        en cola{a.queue_position > 0 ? ` · ${a.queue_position}º` : ""}
      </span>
    );
  if (a.exit_code === 0) return <span className="status done">ok</span>;
  return <span className="status error">exit {a.exit_code ?? "?"}</span>;
}

export function AuditsList() {
  const [audits, setAudits] = useState<AuditSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [stopping, setStopping] = useState<Set<string>>(new Set());

  const anyRunning = (audits ?? []).some((a) => a.is_running);
  const now = useNow(1000, anyRunning);

  async function load() {
    try {
      const list = await api.listAudits();
      // En curso primero; dentro de cada grupo, las más recientes arriba.
      // En curso primero, luego lo encolado por su turno, luego el histórico.
      const rank = (x: AuditSummary) => (x.is_running ? 0 : x.is_queued ? 1 : 2);
      list.sort((a, b) =>
        rank(a) !== rank(b)
          ? rank(a) - rank(b)
          : a.is_queued && b.is_queued
            ? a.queue_position - b.queue_position
            : b.started_at - a.started_at,
      );
      setAudits(list);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, []);

  function toggleExpand(auditId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(auditId)) next.delete(auditId);
      else next.add(auditId);
      return next;
    });
  }

  async function handleStop(auditId: string) {
    setStopping((prev) => new Set(prev).add(auditId));
    try {
      await api.stopAudit(auditId);
    } catch {
      /* el polling reflejará el estado real */
    } finally {
      setStopping((prev) => {
        const next = new Set(prev);
        next.delete(auditId);
        return next;
      });
      load();
    }
  }

  function elapsedOf(a: AuditSummary): string {
    if (a.finished_at != null) {
      return formatDuration(a.finished_at - a.started_at);
    }
    // En curso: reloj con segundos, avanza con el ticker local.
    return formatElapsedClock(now / 1000 - a.started_at);
  }

  return (
    <div>
      <div className="headline">
        <h2>Ejecuciones</h2>
        <span className="tag">
          {audits == null
            ? "cargando"
            : `${audits.filter((a) => a.is_running).length} en curso · ` +
              `${audits.filter((a) => a.is_queued).length} en cola · ` +
              `${audits.length} total`}
        </span>
      </div>

      {error && <div className="error"><strong>error</strong> {error}</div>}

      {audits != null && audits.length === 0 && (
        <div className="empty">
          Sin ejecuciones en esta sesión.{" "}
          <Link to="/launch">Lanzar una auditoría →</Link>
        </div>
      )}

      {audits != null && audits.length > 0 && (
        <table>
          <thead>
            <tr>
              <th></th>
              <th>id</th>
              <th>target</th>
              <th>estado</th>
              <th>inicio</th>
              <th>duración</th>
              <th>líneas</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {audits.map((a) => {
              const isOpen = expanded.has(a.audit_id);
              return (
                <AuditRow
                  key={a.audit_id}
                  audit={a}
                  isOpen={isOpen}
                  elapsed={elapsedOf(a)}
                  stopping={stopping.has(a.audit_id)}
                  onToggle={() => toggleExpand(a.audit_id)}
                  onStop={() => handleStop(a.audit_id)}
                />
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AuditRow({
  audit: a,
  isOpen,
  elapsed,
  stopping,
  onToggle,
  onStop,
}: {
  audit: AuditSummary;
  isOpen: boolean;
  elapsed: string;
  stopping: boolean;
  onToggle: () => void;
  onStop: () => void;
}) {
  return (
    <>
      <tr>
        <td style={{ width: "2rem" }}>
          <button
            type="button"
            className="secondary"
            onClick={onToggle}
            title={isOpen ? "ocultar salida" : "ver salida en vivo"}
            style={{ padding: ".15rem .5rem" }}
          >
            {isOpen ? "▾" : "▸"}
          </button>
        </td>
        <td className="mono">
          <Link to={`/audits/${a.audit_id}`}>{a.audit_id}</Link>
        </td>
        <td className="mono">
          {a.target_ip}
          {a.replica_total > 1 && (
            <span className="tag" style={{ marginLeft: ".4rem", fontSize: ".68rem" }}>
              réplica {a.replica_index}/{a.replica_total}
            </span>
          )}
          {/* Un run sin PolicyEngine no ejercita el mismo sistema que el resto:
              debe ser distinguible de un vistazo al comparar resultados. */}
          {a.policy_disabled && (
            <span
              className="tag"
              title="Lanzada con --no-policy: shell directo, sin allowlist de comandos"
              style={{ marginLeft: ".4rem", fontSize: ".68rem" }}
            >
              ⚠ sin policy
            </span>
          )}
        </td>
        <td>{statusChip(a)}</td>
        <td className="mono" style={{ fontSize: ".78rem" }}>
          {formatEpoch(a.started_at)}
        </td>
        <td className="mono">
          {elapsed}
          {a.is_running && <span className="dim"> ↻</span>}
        </td>
        <td className="mono">{a.log_lines}</td>
        <td>
          <div className="row" style={{ gap: ".4rem" }}>
            <Link to={`/audits/${a.audit_id}`} className="tag" style={{ padding: ".2rem .5rem" }}>
              abrir
            </Link>
            {(a.is_running || a.is_queued) && (
              <button
                type="button"
                onClick={onStop}
                disabled={stopping}
                style={{
                  background: "#b3261e", color: "#fff", border: "none",
                  padding: ".2rem .55rem", borderRadius: ".4rem",
                  cursor: stopping ? "default" : "pointer",
                  opacity: stopping ? 0.7 : 1, fontSize: ".78rem",
                }}
              >
                {stopping ? "…" : "⏹"}
              </button>
            )}
          </div>
        </td>
      </tr>
      {isOpen && (
        <tr>
          <td colSpan={8} style={{ padding: ".5rem .25rem 1rem" }}>
            <LiveTerminal url={api.streamUrl(a.audit_id)} maxHeightVh={38} />
          </td>
        </tr>
      )}
    </>
  );
}
