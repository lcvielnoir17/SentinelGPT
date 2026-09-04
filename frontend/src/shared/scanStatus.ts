/**
 * Canonical scan-status → CSS pill mapping.
 *
 * Previously copy-pasted in DashboardPage, ScansPage, and ScanDetailPage.
 * Takes a plain string so feature modules don't couple to each other.
 */
export function statusPillClass(status: string): string {
  switch (status) {
    case "REPORT_READY":
      return "pill pill-ok";
    case "REPORT_READY_DEGRADED":
      return "pill pill-warn";
    case "REJECTED":
    case "CANCELLED":
      return "pill pill-bad";
    case "RUNNING":
    case "SCAN_COMPLETE":
    case "AI_ANALYSIS":
    case "PARTIALLY_COMPLETE":
      return "pill pill-info";
    case "QUEUED":
    default:
      return "pill pill-muted";
  }
}
