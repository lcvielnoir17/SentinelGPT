/**
 * Canonical display-formatting helpers (dates, truncation).
 *
 * Every call site previously inlined `new Date(...).toLocaleString()` and
 * two copies of `truncate` existed. Output is byte-identical to the
 * inlined versions: missing dates render as "—".
 */
export function formatDateTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…`;
}
