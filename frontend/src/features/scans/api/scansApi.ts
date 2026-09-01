/**
 * Scan feature API bindings (SRS Chapter 5, Section 6).
 *
 * Response shapes are the camelCase JSON the FastAPI backend actually emits
 * (verified against backend/src/api/routes/scan_routes.py).
 */

import { apiRequest } from "../../../services/apiClient";

export type ScanProfile = "quick-check" | "standard" | "full-assessment";

export type ScanStatusCode =
  | "QUEUED"
  | "RUNNING"
  | "PARTIALLY_COMPLETE"
  | "SCAN_COMPLETE"
  | "AI_ANALYSIS"
  | "REPORT_READY"
  | "REPORT_READY_DEGRADED"
  | "REJECTED"
  | "CANCELLED";

export interface Scan {
  id: string;
  targetId: string;
  scanProfile: ScanProfile;
  status: ScanStatusCode;
  initiatedBy: string;
  authorizationAttestationId: string;
  queuedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: string;
  evidence: string;
  location: string;
  recommendation: string;
  createdAt: string;
}

export interface Assessment {
  available: boolean;
  provider: string;
  model: string;
  promptSchemaVersion: string;
  outputSchemaVersion: string;
  failureKind: string | null;
  unsupportedClaimCount: number;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface FindingExplanation {
  available: boolean;
  validationStatus: string;
  fallbackReason?: string;
  explanation?: Record<string, unknown>;
}

export function createScan(payload: { targetId: string; scanProfile?: ScanProfile }): Promise<Scan> {
  return apiRequest<Scan>("/scans", {
    method: "POST",
    body: {
      targetId: payload.targetId,
      scanProfile: payload.scanProfile ?? "quick-check",
    },
  });
}

export function listScans(params: { targetId?: string; status?: string; limit?: number } = {}): Promise<Scan[]> {
  const search = new URLSearchParams();
  if (params.targetId) search.set("targetId", params.targetId);
  if (params.status) search.set("status", params.status);
  if (params.limit) search.set("limit", String(params.limit));
  const query = search.toString();
  return apiRequest<Scan[]>(`/scans${query ? `?${query}` : ""}`);
}

export function getScan(id: string): Promise<Scan> {
  return apiRequest<Scan>(`/scans/${id}`);
}

export function cancelScan(id: string): Promise<Scan> {
  return apiRequest<Scan>(`/scans/${id}/cancel`, { method: "POST" });
}

export function listFindings(scanId: string): Promise<Finding[]> {
  return apiRequest<Finding[]>(`/scans/${scanId}/findings`);
}

export function getAssessment(scanId: string): Promise<Assessment> {
  return apiRequest<Assessment>(`/scans/${scanId}/assessment`);
}

export function getFindingExplanation(
  scanId: string,
  findingId: string,
): Promise<FindingExplanation> {
  return apiRequest<FindingExplanation>(`/scans/${scanId}/findings/${findingId}/explanation`);
}

/**
 * Create a new scan linked to a previous scan (rescan).
 *
 * Backend returns 201 with the new scan's `ScanResponse`. The new scan
 * inherits the original's target, profile, and authorization attestation
 * (SRS Ch5 §6 + Ch9); it is queued immediately, not executed inline.
 *
 * Cross-tenant source scans surface as 404 NOT_FOUND (no existence leak).
 */
export function rescanScan(scanId: string): Promise<Scan> {
  return apiRequest<Scan>(`/scans/${scanId}/rescan`, { method: "POST" });
}

/**
 * Compare findings between two scans of the same target.
 *
 * Backend returns a `CompareResponse` with four groups (`new`,
 * `persistent`, `resolved`, `regressed`), each a list of
 * `FindingCompareItem`. The two scans must target the same target —
 * otherwise the backend raises 409 SCAN_INVALID_STATE. Cross-tenant
 * scans surface as 404 NOT_FOUND.
 */
export interface FindingCompareItem {
  id: string;
  fingerprint: string;
  title: string;
}

export interface CompareResponse {
  new: FindingCompareItem[];
  persistent: FindingCompareItem[];
  resolved: FindingCompareItem[];
  regressed: FindingCompareItem[];
}

export function compareScans(scanAId: string, scanBId: string): Promise<CompareResponse> {
  return apiRequest<CompareResponse>(`/scans/${scanAId}/compare/${scanBId}`);
}
