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
  /** Per-request timeout in milliseconds. When exceeded the request is
   * aborted and an `ApiError` with code `TIMEOUT` (status 0) is thrown so
   * callers can always leave a loading state and offer a retry. When
   * omitted the request waits indefinitely (pre-existing behavior for
   * callers that manage their own lifecycle). */
  timeoutMs?: number;
  /** Optional external abort signal (e.g. component unmount). An external
   * abort surfaces as an `ApiError` with code `ABORTED` (status 0). */
  signal?: AbortSignal;
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

/**
 * Silent session refresh (AuthContext never calls `/auth/refresh` directly).
 *
 * The access JWT lives 15 minutes while the refresh credential lives 7
 * days. When any data request answers 401, exactly one refresh flight runs
 * (concurrent 401s share it) and the original request retries once against
 * the rotated cookies. Only when the refresh itself fails is the session
 * genuinely dead and the unauthorized handler fired — so idle users are
 * not bounced to /login every 15 minutes.
 *
 * The refresh endpoint requires the `X-Refresh-Request` CSRF header and
 * the HttpOnly refresh cookie; both attach automatically same-origin.
 */
let refreshInflight: Promise<boolean> | null = null;

function isSessionEndpoint(path: string): boolean {
  return path === "/auth/refresh" || path === "/auth/logout";
}

async function tryRefreshSession(): Promise<boolean> {
  if (!refreshInflight) {
    refreshInflight = (async () => {
      try {
        const response = await fetch(`${BASE_URL}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-Refresh-Request": "1" },
        });
        return response.ok;
      } catch {
        return false;
      } finally {
        refreshInflight = null;
      }
    })();
  }
  return refreshInflight;
}

async function doFetch(path: string, init: RequestInit): Promise<Response> {
  const response = await fetch(`${BASE_URL}${path}`, init);
  // Refresh exactly once per request; auth endpoints and already-retried
  // requests never loop (the retry below goes through no further refresh).
  if (response.status === 401 && !isSessionEndpoint(path)) {
    if (await tryRefreshSession()) {
      return fetch(`${BASE_URL}${path}`, init);
    }
  }
  return response;
}

/**
 * Combine a per-request timeout with an optional external abort signal
 * into a single signal for fetch, reporting which side fired.
 */
function watchAbort(
  timeoutMs: number | undefined,
  externalSignal: AbortSignal | undefined,
): { signal: AbortSignal | undefined; done: () => void; timedOut: () => boolean } {
  if (timeoutMs === undefined && externalSignal === undefined) {
    return { signal: undefined, done: () => {}, timedOut: () => false };
  }
  const controller = new AbortController();
  let firedTimeout = false;
  const onExternalAbort = (): void => controller.abort();
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (externalSignal !== undefined) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      externalSignal.addEventListener("abort", onExternalAbort, { once: true });
    }
  }
  if (timeoutMs !== undefined) {
    timer = setTimeout(() => {
      firedTimeout = true;
      controller.abort();
    }, timeoutMs);
  }
  return {
    signal: controller.signal,
    done: () => {
      if (timer !== undefined) clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
    },
    timedOut: () => firedTimeout,
  };
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

  const abort = watchAbort(options.timeoutMs, options.signal);
  if (abort.signal !== undefined) {
    init.signal = abort.signal;
  }
  let response: Response;
  try {
    response = await doFetch(path, init);
  } catch (err) {
    abort.done();
    if (abort.timedOut()) {
      throw new ApiError(0, "TIMEOUT", "The request timed out; try again.", null);
    }
    if (options.signal?.aborted) {
      throw new ApiError(0, "ABORTED", "The request was cancelled.", null);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      0,
      "NETWORK_ERROR",
      "Unable to reach the SentinelGPT API; check your connection and try again.",
      null,
    );
  }
  abort.done();

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
 *
 * 401s go through the same silent-refresh path; a surviving 401 still
 * fires the unauthorized handler so an expired session redirects to
 * /login instead of stranding the download with a generic error.
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
  const response = await doFetch(path, init);
  if (response.status === 401) {
    notifyUnauthorized();
  }
  return response;
}