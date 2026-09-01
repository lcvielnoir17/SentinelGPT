/**
 * Centralized API client (SRS Chapter 3, Section 12 / Chapter 2, Section 4).
 *
 * All backend access goes through this module — components never call
 * fetch() directly. Same-origin requests only; credentials mode is
 * "same-origin" so that Phase 1's HttpOnly cookies attach automatically
 * without JavaScript ever reading token material.
 */

export const BASE_URL = "/api/v1";

/** Structured error surfaced from the SRS error envelope. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string; requestId?: string };
}

export interface ApiRequestOptions {
  method?: string;
  body?: unknown;
  /** Extra request headers — used by `/auth/refresh` and `/auth/logout`
   * to set the required `X-Refresh-Request` CSRF header. */
  headers?: Record<string, string>;
}

/**
 * Register a one-shot callback for unauthorized responses.
 *
 * The backend signals a dead session by returning 401 (expired access JWT,
 * revoked refresh credential, etc.). A single registered handler
 * (typically `AuthProvider`) reacts by clearing in-memory state and
 * navigating the user back to `/login`.
 */
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

function notifyUnauthorized(): void {
  if (unauthorizedHandler !== null) {
    unauthorizedHandler();
  }
}

export async function apiRequest<T>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
  }

  const init: RequestInit = {
    method: options.method ?? "GET",
    credentials: "same-origin",
  };
  if (Object.keys(headers).length > 0) {
    init.headers = headers;
  }
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
  }

  const response = await fetch(`${BASE_URL}${path}`, init);

  if (response.status === 401) {
    notifyUnauthorized();
    let code = `HTTP_${response.status}`;
    let message = response.statusText || "Request failed.";
    let requestId: string | null = null;
    try {
      const payload = (await response.json()) as ErrorEnvelope;
      if (payload.error) {
        code = payload.error.code ?? code;
        message = payload.error.message ?? message;
        requestId = payload.error.requestId ?? null;
      }
    } catch {
      // Non-JSON error body — keep HTTP defaults.
    }
    throw new ApiError(response.status, code, message, requestId);
  }

  if (!response.ok) {
    let code = `HTTP_${response.status}`;
    let message = response.statusText || "Request failed.";
    let requestId: string | null = null;
    try {
      const payload = (await response.json()) as ErrorEnvelope;
      if (payload.error) {
        code = payload.error.code ?? code;
        message = payload.error.message ?? message;
        requestId = payload.error.requestId ?? null;
      }
    } catch {
      // Non-JSON error body — keep HTTP defaults.
    }
    throw new ApiError(response.status, code, message, requestId);
  }

  // 204 No Content has no body — return undefined so callers like
  // `POST /auth/logout` and `DELETE /targets/{id}` don't crash trying
  // to parse JSON out of an empty stream.
  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

/**
 * Like apiRequest but returns the raw Response — used for blob downloads
 * (e.g. report export) where the JSON envelope isn't applicable.
 */
export async function apiRequestRaw(
  path: string,
  options: ApiRequestOptions = {},
): Promise<Response> {
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
  }
  const init: RequestInit = {
    method: options.method ?? "GET",
    credentials: "same-origin",
  };
  if (Object.keys(headers).length > 0) {
    init.headers = headers;
  }
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
  }
  return fetch(`${BASE_URL}${path}`, init);
}