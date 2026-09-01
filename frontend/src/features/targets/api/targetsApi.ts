/**
 * Target feature API bindings (SRS Chapter 5, Section 4 + Section 5).
 *
 * Response shapes are the camelCase JSON the FastAPI backend actually emits
 * (verified against backend/src/api/routes/target_routes.py and
 * backend/src/api/routes/attestation_routes.py).
 */

import { apiRequest } from "../../../services/apiClient";

export interface Target {
  id: string;
  hostname: string;
  url: string;
  ownerOrganizationId: string | null;
  ownerUserId: string | null;
  isArchived: boolean;
  createdAt: string;
  status: string;
}

export interface PageInfo {
  nextCursor: string | null;
  hasNextPage: boolean;
}

export interface TargetListResponse {
  items: Target[];
  pageInfo: PageInfo;
}

export interface Attestation {
  id: string;
  targetId: string;
  method: string;
  status: string;
  expiresAt: string | null;
  evidenceFileRef: string | null;
  revokedAt: string | null;
  revokedReason: string | null;
  createdAt: string;
}

export function listTargets(params: { includeArchived?: boolean } = {}): Promise<TargetListResponse> {
  const search = new URLSearchParams();
  if (params.includeArchived) search.set("includeArchived", "true");
  const query = search.toString();
  return apiRequest<TargetListResponse>(`/targets${query ? `?${query}` : ""}`);
}

export function createTarget(payload: { hostname: string; url: string }): Promise<Target> {
  return apiRequest<Target>("/targets", { method: "POST", body: payload });
}

export function getTarget(id: string): Promise<Target> {
  return apiRequest<Target>(`/targets/${id}`);
}

export function setTargetArchived(id: string, isArchived: boolean): Promise<Target> {
  return apiRequest<Target>(`/targets/${id}`, {
    method: "PATCH",
    body: { isArchived },
  });
}

export function listAttestations(targetId: string): Promise<Attestation[]> {
  return apiRequest<Attestation[]>(`/targets/${targetId}/attestations`);
}

export function createSelfAttestation(targetId: string): Promise<Attestation> {
  return apiRequest<Attestation>(`/targets/${targetId}/attestations`, {
    method: "POST",
    body: { method: "SELF_ATTESTATION" },
  });
}
