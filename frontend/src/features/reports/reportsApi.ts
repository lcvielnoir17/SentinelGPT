/**
 * Report export (SRS Chapter 10, Section 4).
 *
 * Reports are rendered server-side and returned as either JSON or CSV.
 * This client wraps the raw fetch so the report bytes can be saved with
 * the correct filename + content-type without going through the JSON
 * envelope used by apiRequest.
 */

import { apiRequestRaw } from "../../services/apiClient";

export type ReportFormat = "json" | "csv";

export async function downloadScanReport(
  scanId: string,
  format: ReportFormat,
): Promise<{ blob: Blob; filename: string }> {
  const response = await apiRequestRaw(`/scans/${scanId}/report?format=${format}`);
  if (!response.ok) {
    throw new Error(`Report download failed: HTTP ${response.status}`);
  }
  const blob = await response.blob();
  const ext = format === "csv" ? "csv" : "json";
  return { blob, filename: `sentinelgpt-scan-${scanId}.${ext}` };
}
