/** Helpers de formato compartidos entre páginas. */

/** Convierte "yyyymmdd_hhmmss" (o ISO) a "yyyy-mm-dd hh:mm:ss". */
export function formatTimestamp(s: string | null | undefined): string {
  if (!s) return "—";
  // Caso aggregador: "20260516_142935"
  const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(s);
  if (m) return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}`;
  // Si es un timestamp epoch (segundos)
  if (/^\d{9,10}(\.\d+)?$/.test(s)) {
    const d = new Date(Number(s) * 1000);
    if (!isNaN(d.getTime())) return formatDate(d);
  }
  // Intento ISO genérico
  const d = new Date(s);
  if (!isNaN(d.getTime())) return formatDate(d);
  return s;
}

/** Formatea un epoch (segundos) numérico. */
export function formatEpoch(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const d = new Date(seconds * 1000);
  if (isNaN(d.getTime())) return "—";
  return formatDate(d);
}

function pad(n: number): string {
  return n.toString().padStart(2, "0");
}

function formatDate(d: Date): string {
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/** Duración relativa breve, e.g. "12s", "3m", "2h". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || seconds < 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

/** Reloj de duración con resolución de segundo, e.g. "0:42", "16:04", "1:02:33".
 *  Para contadores en vivo: con formatDuration (>60s redondea a minutos) el
 *  contador solo cambiaría una vez por minuto y parecería congelado.
 */
export function formatElapsedClock(seconds: number | null | undefined): string {
  if (seconds == null || seconds < 0) return "—";
  const total = Math.floor(seconds);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}:${pad(m)}:${pad(s)}`;
  return `${m}:${pad(s)}`;
}
