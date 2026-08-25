/**
 * Auth feature API bindings (SRS Chapter 5, Section 2 contract shapes).
 */

import { apiRequest } from "../../../services/apiClient";

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
