/**
 * Organization & membership API bindings (SRS Chapter 5, Section 3).
 *
 * The backend is authoritative for ADMIN permissions and tenant isolation.
 * The frontend never invents authorization rules — it surfaces backend
 * 403 / 404 envelopes verbatim and treats "not visible" identically to
 * "not found" so cross-organization existence cannot be inferred.
 *
 * Response shapes are the camelCase JSON the FastAPI backend actually
 * emits (verified against backend/src/api/routes/organization_routes.py
 * and the regenerated openapi.json).
 */

import { apiRequest } from "../../../services/apiClient";

export type OrganizationRole = "ADMIN" | "MEMBER";

export interface Organization {
  id: string;
  name: string;
  createdAt: string;
}

export interface Membership {
  id: string;
  organizationId: string;
  userId: string;
  role: OrganizationRole;
  createdAt: string;
}

export function getOrganization(orgId: string): Promise<Organization> {
  return apiRequest<Organization>(`/organizations/${orgId}`);
}

export function createOrganization(payload: { name: string }): Promise<Organization> {
  return apiRequest<Organization>("/organizations", {
    method: "POST",
    body: { name: payload.name.trim() },
  });
}

export function listMembers(orgId: string): Promise<Membership[]> {
  return apiRequest<Membership[]>(`/organizations/${orgId}/members`);
}

/**
 * Add a member by user id. The backend's `AddMemberRequest` schema
 * documents the field as `userId` (a UUID); the older `user_id` alias
 * is also accepted for backward compatibility, but the public contract
 * surface is the camelCase key.
 */
export function addMember(
  orgId: string,
  payload: { userId: string; role: OrganizationRole },
): Promise<Membership> {
  return apiRequest<Membership>(`/organizations/${orgId}/members`, {
    method: "POST",
    body: { userId: payload.userId, role: payload.role },
  });
}

export function changeMemberRole(
  orgId: string,
  userId: string,
  payload: { role: OrganizationRole },
): Promise<Membership> {
  return apiRequest<Membership>(`/organizations/${orgId}/members/${userId}`, {
    method: "PATCH",
    body: { role: payload.role },
  });
}

export function removeMember(orgId: string, userId: string): Promise<void> {
  return apiRequest<void>(`/organizations/${orgId}/members/${userId}`, {
    method: "DELETE",
  });
}