/**
 * Centralized API client (SRS Chapter 3, Section 12 / Chapter 2, Section 4).
 *
 * All backend access goes through this module — components never call
 * fetch() directly. Same-origin requests only; credentials mode is
 * "same-origin" so that Phase 1's HttpOnly cookies attach automatically
 * without JavaScript ever reading token material.
 */

const BASE_URL = "/api/v1";

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

export async function apiRequest<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers: options.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });

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

  return (await response.json()) as T;
}
