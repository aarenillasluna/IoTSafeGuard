/** Lanzar auditoría: pasa por escaneo de subred o introduce IP directa.
 *  Tras START, navega a /audits/:audit_id (terminal en vivo).
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { ModoTanda, ScanResult } from "../types/api";

/** Los dos repartos posibles de una tanda, con lo que cuesta cada uno.
 *
 *  El texto no es decorativo: elegir el modo rápido tiene una consecuencia
 *  metodológica —las réplicas dejan de ser estrictamente comparables— y quien
 *  lo elige tiene que verla en el momento de elegir, no descubrirla al mirar
 *  la varianza. Antes esta pantalla afirmaba «hosts en paralelo · réplicas en
 *  secuencia» mientras enviaba una tanda estrictamente serie: prometía la
 *  opción rápida y ejecutaba la lenta.
 */
const MODOS: {
  id: ModoTanda;
  titulo: string;
  detalle: string;
  reparto: (hosts: number, reps: number) => string;
}[] = [
  {
    id: "secuencial",
    titulo: "una a la vez",
    detalle:
      "Máxima comparabilidad entre réplicas — es el reparto con el que se midió la varianza de la memoria.",
    reparto: (h, r) => `${h * r} auditorías en serie`,
  },
  {
    id: "por_dispositivo",
    titulo: "un dispositivo en paralelo",
    detalle:
      "Una réplica de cada aparato a la vez; las de un mismo aparato siguen en orden. Compiten por la cuota del proveedor LLM, la red y la CPU: si el proveedor limita, unas réplicas acaban conducidas por el modelo de reserva.",
    reparto: (h, r) => `${r} ronda${r === 1 ? "" : "s"} de ${h} a la vez`,
  },
];

export function LaunchAudit() {
  const navigate = useNavigate();

  // Estado del flujo "escanear subred → elegir host".
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [scanTimeout, setScanTimeout] = useState(60);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  // Estado del flujo "IP directa".
  const [directIp, setDirectIp] = useState("");
  const [model, setModel] = useState("");
  const [extraArgs, setExtraArgs] = useState("");
  // PolicyEngine ACTIVO por defecto. El dashboard fijaba `--no-policy` en el
  // código, así que la capa de contención quedaba desactivada sin que el
  // operador lo eligiera ni lo supiera. Desactivarla es ahora una acción
  // deliberada y visible.
  const [disablePolicy, setDisablePolicy] = useState(false);

  // Selección multi-host para lanzamiento concurrente.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [runsPerTarget, setRunsPerTarget] = useState(1);
  // Secuencial por defecto: la comparabilidad entre réplicas no puede depender
  // de que nadie toque un desplegable. El modo rápido se elige, no se hereda.
  const [modo, setModo] = useState<ModoTanda>("secuencial");

  // Estado de lanzamiento.
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setSelected(new Set());
    try {
      const res = await api.scanSubnet(cidr.trim(), scanTimeout);
      setScanResult(res);
    } catch (err) {
      setScanError((err as Error).message);
    } finally {
      setScanning(false);
    }
  }

  function toggleSelected(ip: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }

  function toggleAll() {
    if (!scanResult) return;
    setSelected((prev) =>
      prev.size === scanResult.hosts.length
        ? new Set()
        : new Set(scanResult.hosts.map((h) => h.ip)),
    );
  }

  /** Args comunes (modelo + política + extra) compartidos por single y batch. */
  function commonOptions(): {
    model?: string;
    disable_policy?: boolean;
    extra_args?: string[];
  } {
    const opts: {
      model?: string;
      disable_policy?: boolean;
      extra_args?: string[];
    } = {};
    if (model.trim()) opts.model = model.trim();
    if (disablePolicy) opts.disable_policy = true;
    const args = extraArgs
      .split(/\s+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (args.length > 0) opts.extra_args = args;
    return opts;
  }

  async function launchSelected() {
    if (selected.size === 0 || launching) return;
    setLaunching(true);
    setLaunchError(null);
    try {
      await api.startAuditsBatch({
        target_ips: [...selected],
        runs_per_target: runsPerTarget,
        modo,
        ...commonOptions(),
      });
      navigate("/audits");
    } catch (err) {
      setLaunchError((err as Error).message);
      setLaunching(false);
    }
  }

  /** Lanza contra UN objetivo, por el mismo camino que el lote.
   *
   *  Antes esta ruta llamaba a `startAudit`, que encola una sola ejecución y no
   *  acepta ni réplicas ni reparto: auditar una IP suelta daba un run y auditar
   *  la misma IP marcándola en la lista daba cinco. La diferencia no respondía a
   *  ninguna decisión —era el endpoint que cada botón tenía cableado— y obligaba
   *  a recordar cuál de los dos caminos respetaba los controles de la tanda.
   *  Un objetivo es un lote de uno.
   */
  async function launch(ip: string) {
    setLaunching(true);
    setLaunchError(null);
    try {
      const audits = await api.startAuditsBatch({
        target_ips: [ip],
        runs_per_target: runsPerTarget,
        modo,
        ...commonOptions(),
      });
      // Con una sola réplica se abre su terminal en vivo, que es lo que se
      // espera al lanzar contra una IP concreta. Con varias, la lista: seguir
      // una de cinco mientras las otras esperan turno confunde más que ayuda.
      const primera = audits[0]?.audit_id;
      navigate(runsPerTarget === 1 && primera ? `/audits/${primera}` : "/audits");
    } catch (err) {
      setLaunchError((err as Error).message);
      setLaunching(false);
    }
  }

  async function handleDirect(e: React.FormEvent) {
    e.preventDefault();
    if (!directIp.trim()) return;
    await launch(directIp.trim());
  }

  return (
    <div>
      <div className="headline">
        <h2>Auditar</h2>
        <span className="tag">subnet scan + picker · o IP directa</span>
      </div>

      <h3 style={{ marginTop: 0 }}>Descubrir hosts en una subred</h3>
      <form onSubmit={handleScan} className="row" style={{ marginBottom: "1rem" }}>
        <div style={{ flex: "1 1 260px", maxWidth: 320 }}>
          <input
            type="text"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="192.168.1.0/24"
          />
        </div>
        <div style={{ width: 110 }}>
          <input
            type="text"
            value={String(scanTimeout)}
            onChange={(e) => {
              const n = parseInt(e.target.value, 10);
              if (!isNaN(n) && n > 0) setScanTimeout(n);
              else if (e.target.value === "") setScanTimeout(60);
            }}
            placeholder="timeout (s)"
          />
        </div>
        <button type="submit" disabled={scanning || !cidr.trim()}>
          {scanning ? "escaneando" : "descubrir"}
        </button>
      </form>
      {scanError && (
        <div className="error"><strong>error</strong> {scanError}</div>
      )}

      {scanResult && (
        <>
          <p className="muted" style={{ fontSize: ".82rem" }}>
            {scanResult.host_count} host{scanResult.host_count === 1 ? "" : "s"} en{" "}
            <span className="mono">{scanResult.cidr}</span>
          </p>
          {scanResult.hosts.length === 0 ? (
            <div className="empty">
              Sin hosts en la subred (o sin permisos para ARP).
            </div>
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: "2rem" }}>
                      <input
                        type="checkbox"
                        checked={
                          selected.size === scanResult.hosts.length &&
                          scanResult.hosts.length > 0
                        }
                        onChange={toggleAll}
                        title="seleccionar todos"
                      />
                    </th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Vendor (OUI)</th>
                    <th>Hostname</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.hosts.map((h) => (
                    <tr key={h.ip}>
                      <td>
                        <input
                          type="checkbox"
                          checked={selected.has(h.ip)}
                          onChange={() => toggleSelected(h.ip)}
                        />
                      </td>
                      <td className="mono">{h.ip}</td>
                      <td className="mono">{h.mac || <span className="dim">—</span>}</td>
                      <td>{h.vendor || <span className="dim">—</span>}</td>
                      <td className="mono">{h.hostname || <span className="dim">—</span>}</td>
                      <td>
                        <button
                          type="button"
                          className="secondary"
                          disabled={launching}
                          onClick={() => launch(h.ip)}
                        >
                          auditar
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="stack" style={{ marginTop: ".75rem", gap: ".6rem" }}>
                <div className="row" style={{ gap: ".75rem", alignItems: "center" }}>
                  <label className="row" style={{ gap: ".4rem", alignItems: "center" }}>
                    <span className="dim mono" style={{ fontSize: ".72rem" }}>
                      runs por dispositivo
                    </span>
                    <input
                      type="number"
                      min={1}
                      max={10}
                      value={runsPerTarget}
                      onChange={(e) => {
                        const n = parseInt(e.target.value, 10);
                        if (!isNaN(n)) setRunsPerTarget(Math.min(10, Math.max(1, n)));
                      }}
                      style={{ width: "4.5rem" }}
                    />
                  </label>
                  <label className="row" style={{ gap: ".4rem", alignItems: "center" }}>
                    <span className="dim mono" style={{ fontSize: ".72rem" }}>
                      reparto
                    </span>
                    <select
                      value={modo}
                      onChange={(e) => setModo(e.target.value as ModoTanda)}
                      style={{ minWidth: "14rem" }}
                    >
                      {MODOS.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.titulo}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    disabled={launching || selected.size === 0}
                    onClick={launchSelected}
                  >
                    {launching
                      ? "lanzando…"
                      : `auditar seleccionados (${selected.size}×${runsPerTarget} = ${selected.size * runsPerTarget})`}
                  </button>
                </div>
                {selected.size > 0 && (
                  <div className="stack" style={{ gap: ".2rem" }}>
                    <span className="mono" style={{ fontSize: ".78rem" }}>
                      {MODOS.find((m) => m.id === modo)!.reparto(
                        selected.size,
                        runsPerTarget,
                      )}
                      {modo === "por_dispositivo" && (
                        <span className="dim">
                          {" "}
                          · nunca dos runs contra el mismo aparato
                        </span>
                      )}
                    </span>
                    <span className="dim" style={{ fontSize: ".72rem" }}>
                      {MODOS.find((m) => m.id === modo)!.detalle}
                    </span>
                    <span className="dim" style={{ fontSize: ".72rem" }}>
                      modelo y args extra del formulario de abajo aplican a todas
                    </span>
                  </div>
                )}
              </div>
            </>
          )}
        </>
      )}

      <div className="divider" />

      <h3 style={{ marginTop: 0 }}>O lanzar contra una IP concreta</h3>
      <form onSubmit={handleDirect} className="stack" style={{ maxWidth: 520 }}>
        <label className="stack" style={{ gap: ".25rem" }}>
          <span className="dim mono" style={{ fontSize: ".72rem" }}>target ip</span>
          <input
            type="text"
            value={directIp}
            onChange={(e) => setDirectIp(e.target.value)}
            placeholder="192.168.1.1"
          />
        </label>
        <label className="stack" style={{ gap: ".25rem" }}>
          <span className="dim mono" style={{ fontSize: ".72rem" }}>
            modelo <span className="dim">(opcional, default del .env)</span>
          </span>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="claude-haiku-4-5  ·  claude-sonnet-4-6  ·  us.anthropic.*"
          />
        </label>
        <label className="stack" style={{ gap: ".25rem" }}>
          <span className="dim mono" style={{ fontSize: ".72rem" }}>
            argumentos extra <span className="dim">(separados por espacio)</span>
          </span>
          <input
            type="text"
            value={extraArgs}
            onChange={(e) => setExtraArgs(e.target.value)}
            placeholder="--no-safety --max-turns 30"
          />
        </label>
        <label
          className="row"
          style={{ gap: ".5rem", alignItems: "flex-start" }}
        >
          <input
            type="checkbox"
            checked={disablePolicy}
            onChange={(e) => setDisablePolicy(e.target.checked)}
            style={{ marginTop: ".2rem" }}
          />
          <span className="stack" style={{ gap: ".15rem" }}>
            <span className="mono" style={{ fontSize: ".78rem" }}>
              desactivar PolicyEngine{" "}
              <span className="dim">(--no-policy · modo investigación)</span>
            </span>
            <span className="dim" style={{ fontSize: ".72rem" }}>
              {disablePolicy
                ? "⚠️  el agente ejecutará con shell directo y sin allowlist: sin contención de comandos"
                : "allowlist de binarios y flags activa, sin shell — recomendado"}
            </span>
          </span>
        </label>
        {/* Los mismos controles de tanda que arriba, sobre el mismo estado: si
            una IP suelta es un lote de uno, tiene que admitir réplicas y
            reparto igual que el lote. Vivían solo en el bloque del escaneo, así
            que auditar por IP directa daba siempre una ejecución sin que nadie
            lo hubiera decidido. */}
        <div className="row" style={{ gap: ".75rem", alignItems: "center" }}>
          <label className="row" style={{ gap: ".4rem", alignItems: "center" }}>
            <span className="dim mono" style={{ fontSize: ".72rem" }}>réplicas</span>
            <input
              type="number"
              min={1}
              max={10}
              value={runsPerTarget}
              onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                if (!isNaN(n)) setRunsPerTarget(Math.min(10, Math.max(1, n)));
              }}
              style={{ width: "4.5rem" }}
            />
          </label>
          <label className="row" style={{ gap: ".4rem", alignItems: "center" }}>
            <span className="dim mono" style={{ fontSize: ".72rem" }}>reparto</span>
            <select
              value={modo}
              onChange={(e) => setModo(e.target.value as ModoTanda)}
              style={{ minWidth: "13rem" }}
            >
              {MODOS.map((m) => (
                <option key={m.id} value={m.id}>{m.titulo}</option>
              ))}
            </select>
          </label>
        </div>
        {runsPerTarget > 1 && (
          <span className="dim" style={{ fontSize: ".72rem" }}>
            {MODOS.find((m) => m.id === modo)!.reparto(1, runsPerTarget)} · al
            terminar aparecen todas en la lista de auditorías
          </span>
        )}
        <div>
          <button type="submit" disabled={launching || !directIp.trim()}>
            {launching
              ? "lanzando"
              : runsPerTarget === 1
                ? "lanzar"
                : `lanzar ${runsPerTarget} réplicas`}
          </button>
        </div>
      </form>
      {launchError && (
        <div className="error" style={{ marginTop: ".75rem" }}>
          <strong>error</strong> {launchError}
        </div>
      )}
    </div>
  );
}
