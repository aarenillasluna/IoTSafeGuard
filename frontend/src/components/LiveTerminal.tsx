/** Terminal en vivo conectado por WebSocket.
 *  - Auto-scroll al final, salvo que el usuario suba manualmente (pausa).
 *  - Coloreado básico por substring del log.
 *  - Indicador de líneas y estado de conexión.
 */
import { useEffect, useRef, useState } from "react";
import type { StreamMessage } from "../types/api";

type ConnState = "connecting" | "open" | "closed" | "error" | "done";

interface Line {
  n: number;
  text: string;
  cls: string;
}

function classify(text: string): string {
  // Orden importante: primero error, luego éxito, etc.
  if (/(\bERROR\b|\bFAIL\b|TRACEBACK|EXCEPTION)/i.test(text)) return "line-err";
  if (/(SUCCESS|✅|\bOK\b|CONFIRMED)/.test(text)) return "line-ok";
  if (/(WARNING|WARN|⚠)/i.test(text)) return "line-warn";
  if (/\[AGENT\]|\[TOOL\]|\[MODEL\]/.test(text)) return "line-tool";
  if (/\[INFO\]|\[\+\]|→/.test(text)) return "line-info";
  return "";
}

export interface LiveTerminalProps {
  /** URL ws:// o wss:// del endpoint a conectar. */
  url: string;
  /** Callback cuando el backend envía type:"done". */
  onDone?: (exitCode: number, totalLines: number, elapsed: number) => void;
  /** Altura opcional del bloque. */
  maxHeightVh?: number;
}

export function LiveTerminal({ url, onDone, maxHeightVh }: LiveTerminalProps) {
  const [lines, setLines] = useState<Line[]>([]);
  const [state, setState] = useState<ConnState>("connecting");
  const [autoScroll, setAutoScroll] = useState(true);
  const [copyState, setCopyState] = useState<"idle" | "ok" | "err">("idle");
  const preRef = useRef<HTMLPreElement | null>(null);
  const autoScrollRef = useRef(true);
  const wsRef = useRef<WebSocket | null>(null);

  // Mantener ref sincronizado con el state para usarlo en handlers WS.
  useEffect(() => {
    autoScrollRef.current = autoScroll;
  }, [autoScroll]);

  useEffect(() => {
    setLines([]);
    setState("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      setState("error");
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => setState("open");
    ws.onerror = () => setState("error");
    ws.onclose = () =>
      setState((prev) => (prev === "done" ? "done" : "closed"));

    ws.onmessage = (ev) => {
      let msg: StreamMessage;
      try {
        msg = JSON.parse(ev.data) as StreamMessage;
      } catch {
        return;
      }
      if (msg.type === "line") {
        setLines((prev) => [
          ...prev,
          { n: msg.n, text: msg.data, cls: classify(msg.data) },
        ]);
      } else if (msg.type === "done") {
        setState("done");
        onDone?.(msg.exit_code, msg.total_lines, msg.elapsed_seconds);
      } else if (msg.type === "stopping") {
        setLines((prev) => [
          ...prev,
          { n: prev.length + 1, text: msg.data, cls: "line-warn" },
        ]);
      } else if (msg.type === "error") {
        setLines((prev) => [
          ...prev,
          { n: prev.length + 1, text: `[STREAM ERROR] ${msg.data}`, cls: "line-err" },
        ]);
      }
    };

    return () => {
      try {
        ws.close();
      } catch {
        /* noop */
      }
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  // Auto-scroll cuando llegan líneas nuevas, si el usuario no ha hecho scroll-up.
  useEffect(() => {
    if (!autoScrollRef.current) return;
    const el = preRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  function handleScroll() {
    const el = preRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    if (nearBottom && !autoScrollRef.current) setAutoScroll(true);
    if (!nearBottom && autoScrollRef.current) setAutoScroll(false);
  }

  async function copyAll() {
    const text = lines.map((l) => l.text).join("\n");
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback para contextos sin Clipboard API (http en LAN, etc.)
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopyState("ok");
    } catch {
      setCopyState("err");
    }
    setTimeout(() => setCopyState("idle"), 1800);
  }

  const copyLabel =
    copyState === "ok" ? "copiado" : copyState === "err" ? "no se pudo copiar" : "copiar log";

  const statusLabel: Record<ConnState, string> = {
    connecting: "conectando",
    open: "en vivo",
    closed: "desconectado",
    error: "error de conexión",
    done: "finalizado",
  };
  const statusCls: Record<ConnState, string> = {
    connecting: "connecting",
    open: "live",
    closed: "closed",
    error: "error",
    done: "done",
  };

  return (
    <div className="stack">
      <div className="row spread">
        <div className="row">
          <span className={`status ${statusCls[state]}`}>{statusLabel[state]}</span>
          <span className="dim mono" style={{ fontSize: ".75rem" }}>
            {lines.length} líneas
          </span>
          {!autoScroll && (
            <span className="tag">auto-scroll en pausa</span>
          )}
        </div>
        <div className="flex">
          <button
            type="button"
            className="secondary"
            onClick={copyAll}
            disabled={lines.length === 0}
            title={`Copia las ${lines.length} líneas al portapapeles`}
          >
            {copyLabel}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setAutoScroll(true);
              const el = preRef.current;
              if (el) el.scrollTop = el.scrollHeight;
            }}
          >
            ir al final
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setLines([])}
          >
            limpiar
          </button>
        </div>
      </div>
      <pre
        ref={preRef}
        className="terminal"
        style={maxHeightVh ? { maxHeight: `${maxHeightVh}vh` } : undefined}
        onScroll={handleScroll}
      >
        {lines.length === 0 ? (
          <span className="muted">
            {state === "connecting" ? "Esperando salida del agente…" : "Sin líneas."}
          </span>
        ) : (
          lines.map((l) => (
            <div key={l.n} className={l.cls}>
              {l.text}
            </div>
          ))
        )}
      </pre>
    </div>
  );
}
