/**
 * Audit log API bindings (SRS Chapter 5, Section 12).
 *
 * The backend's audit-log endpoints are authoritative: a non-visible entry
 * (e.g. another tenant's row) returns 404, indistinguishable from a
 * nonexistent row. The frontend must never invent cross-tenant filtering
 * rules — let the backend decide and surface its 404 verbatim.
 *
 * Response shapes are the camelCase JSON the FastAPI backend actually
 * emits (verified against backend/src/api/routes/audit_routes.py).
 */

import { apiRequest } from "../../../services/apiClient";

export interface AuditEntry {
  id: string;
  actionCode: string;
  entityType: string;
  entityId: string;
  actorUserId: string | null;
  metadata: Record<string, unknown>;
  occurredAt: string;
}

/**
 * Query audit entries visible to the current user.
 *
 * Backend filter parameters (camelCase aliases — kept as-is to match the
 * verified public contract):
 *   entityType, entityId, actionCode, dateFrom, dateTo, limit (1-200)
 */
export interface ListAuditEntriesParams {
  entityType?: string;
  entityId?: string;
  actionCode?: string;
  dateFrom?: string;
  dateTo?: string;
  limit?: number;
}

export function listAuditEntries(
  params: ListAuditEntriesParams = {},
): Promise<AuditEntry[]> {
  const search = new URLSearchParams();
  if (params.entityType) search.set("entityType", params.entityType);
  if (params.entityId) search.set("entityId", params.entityId);
  if (params.actionCode) search.set("actionCode", params.actionCode);
  if (params.dateFrom) search.set("dateFrom", params.dateFrom);
  if (params.dateTo) search.set("dateTo", params.dateTo);
  if (params.limit !== undefined) search.set("limit", String(params.limit));
  const query = search.toString();
  return apiRequest<AuditEntry[]>(`/audit-log${query ? `?${query}` : ""}`);
}

/**
 * Fetch a single audit entry by id.
 *
 * Backend returns 404 NOT_FOUND for both "row doesn't exist" and
 * "row exists but is not visible to this principal" (SRS Ch5 §14
 * fail-closed isolation). Callers must surface this as a generic
 * "audit entry not found" — never imply the entry exists for another
 * tenant.
 */
export function getAuditEntry(entryId: string): Promise<AuditEntry> {
  return apiRequest<AuditEntry>(`/audit-log/${entryId}`);
}