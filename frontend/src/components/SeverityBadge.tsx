/** Severidad y estado: bullet de color + texto, sin background semáforo. */
export function SeverityBadge({ value }: { value: string | null | undefined }) {
  const raw = (value || "unknown").toLowerCase();
  const known = ["critical", "high", "medium", "low", "info", "negligible"];
  const cls = known.includes(raw) ? raw : "";
  return <span className={`sev ${cls}`}>{raw}</span>;
}

export function ConfirmedBadge({ confirmed }: { confirmed: boolean }) {
  return (
    <span className={`sev ${confirmed ? "confirmed" : "dismissed"}`}>
      {confirmed ? "confirmado" : "descartado"}
    </span>
  );
}
