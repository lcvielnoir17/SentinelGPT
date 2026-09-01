/**
 * Auth feature API bindings (SRS Chapter 5, Section 2 contract shapes).
 */

import { apiRequest } from "../../../services/apiClient";

/**
 * CSRF mitigation header required by `/auth/refresh` and `/auth/logout`
 * (SRS Ch2 §9). Same-origin JS sets this; cross-site form posts cannot.
 */
export const REFRESH_REQUEST_HEADER = "X-Refresh-Request";
const REFRESH_REQUEST_VALUE = "1";

function refreshRequestHeaders(): Record<string, string> {
  return { [REFRESH_REQUEST_HEADER]: REFRESH_REQUEST_VALUE };
}

export interface UserAccount {
  id: string;
  email: string;
  mfaEnabled: boolean;
  organizations: string[];
}

export interface LoginResponse {
  user: UserAccount;
  /** Access-token lifetime in seconds once Phase 1 issues cookie sessions. */
  expiresIn: number;
}

export interface RegisterResponse {
  id: string;
  email: string;
  createdAt: string;
}

export function register(email: string, password: string): Promise<RegisterResponse> {
  return apiRequest<RegisterResponse>("/auth/register", {
    method: "POST",
    body: { email, password },
  });
}

export function login(email: string, password: string): Promise<LoginResponse> {
  return apiRequest<LoginResponse>("/auth/login", {
    method: "POST",
    body: { email, password },
  });
}

/**
 * Session-restore probe.
 *
 * Returns the current `UserInfo` when the request carries a valid access
 * JWT cookie, and the backend's structured 401 envelope when it does not.
 * Called once on SPA startup so a returning user does not see a
 * `/login` flash.
 */
export function me(): Promise<UserAccount> {
  return apiRequest<UserAccount>("/auth/me");
}

/**
 * Revoke the active refresh credential and clear both auth cookies
 * server-side (SRS Ch5 §2). Idempotent: calling on an already-revoked
 * session still returns 204.
 */
export async function logout(): Promise<void> {
  await apiRequest<void>("/auth/logout", {
    method: "POST",
    headers: refreshRequestHeaders(),
  });
}
