/**
 * Silent session refresh in the centralized API client.
 *
 * The access JWT lives 15 minutes against a 7-day refresh credential.
 * Contract:
 * 1. a 401 on a data request triggers exactly one refresh POST and retries
 *    the original request once;
 * 2. concurrent 401s share a single refresh flight;
 * 3. a failed refresh fires the unauthorized handler and throws;
 * 4. /auth/* endpoints never trigger refresh (no loops);
 * 5. apiRequestRaw applies the same refresh path and notifies on a
 *    surviving 401 (report downloads redirect instead of stranding).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  apiRequest,
  apiRequestRaw,
  setUnauthorizedHandler,
} from "./apiClient";

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installFetch(impl: (...args: unknown[]) => Promise<Response>): void {
  vi.stubGlobal("fetch", vi.fn(impl));
}

afterEach(() => {
  vi.unstubAllGlobals();
  setUnauthorizedHandler(null);
});

describe("apiRequest refresh", () => {
  it("refreshes once and retries the original request", async () => {
    const calls: string[] = [];
    installFetch(async (url: unknown, init: unknown) => {
      const method = (init as RequestInit).method ?? "GET";
      calls.push(`${method} ${url}`);
      if (url === "/api/v1/auth/refresh") return new Response(null, { status: 200 });
      if (calls.filter((c) => c.startsWith("GET")).length === 1) {
        return jsonResponse({ error: { code: "UNAUTHENTICATED" } }, 401);
      }
      return jsonResponse({ items: [] }, 200);
    });

    const notified: unknown[] = [];
    setUnauthorizedHandler(() => notified.push(true));
    const body = await apiRequest<{ items: unknown[] }>("/targets");

    expect(body).toEqual({ items: [] });
    expect(calls).toEqual(["GET /api/v1/targets", "POST /api/v1/auth/refresh", "GET /api/v1/targets"]);
    expect(notified).toEqual([]);
  });

  it("sends the CSRF header on the refresh POST", async () => {
    let refreshHeaders: Record<string, string> = {};
    let first = true;
    installFetch(async (url: unknown, init: unknown) => {
      if (url === "/api/v1/auth/refresh") {
        refreshHeaders = ((init as RequestInit).headers ?? {}) as Record<string, string>;
        return new Response(null, { status: 200 });
      }
      if (first) {
        first = false;
        return jsonResponse({}, 401);
      }
      return jsonResponse({ ok: true }, 200);
    });
    await apiRequest("/targets");
    expect(refreshHeaders["X-Refresh-Request"]).toBe("1");
  });

  it("shares a single refresh flight across concurrent 401s", async () => {
    let refreshPosts = 0;
    installFetch(async (url: unknown) => {
      if (url === "/api/v1/auth/refresh") {
        refreshPosts += 1;
        await new Promise((r) => setTimeout(r, 10));
        return new Response(null, { status: 200 });
      }
      return jsonResponse({}, 401);
    });
    setUnauthorizedHandler(() => {});

    const results = await Promise.allSettled([apiRequest("/a"), apiRequest("/b")]);
    expect(refreshPosts).toBe(1);
    // Retries still 401 (mock never succeeds) → both throw, handler fired.
    expect(results.map((r) => r.status)).toEqual(["rejected", "rejected"]);
  });

  it("notifies and throws when the refresh itself fails", async () => {
    installFetch(async (url: unknown) => {
      if (url === "/api/v1/auth/refresh") return jsonResponse({}, 401);
      return jsonResponse({ error: { code: "UNAUTHENTICATED", message: "expired" } }, 401);
    });
    const notified: unknown[] = [];
    setUnauthorizedHandler(() => notified.push(true));

    await expect(apiRequest("/targets")).rejects.toBeInstanceOf(ApiError);
    expect(notified).toHaveLength(1);
  });

  it("never refreshes for auth endpoints", async () => {
    const calls: string[] = [];
    installFetch(async (url: unknown) => {
      calls.push(String(url));
      return jsonResponse({}, 401);
    });
    setUnauthorizedHandler(() => {});

    await expect(apiRequest<void>("/auth/logout", { method: "POST" })).rejects.toBeInstanceOf(
      ApiError,
    );
    expect(calls).toEqual(["/api/v1/auth/logout"]);
  });
});

describe("apiRequestRaw refresh", () => {  it("retries after refresh and notifies on surviving 401", async () => {
    const seen = new Set<string>();
    installFetch(async (url: unknown) => {
      const key = String(url);
      if (key === "/api/v1/auth/refresh") return new Response(null, { status: 200 });
      // /scans/x recovers after refresh; /scans/y stays unauthorized.
      if (key.endsWith("/scans/y/report?format=csv")) return new Response("no", { status: 401 });
      if (!seen.has(key)) {
        seen.add(key);
        return new Response("no", { status: 401 });
      }
      return new Response("a,b", { status: 200 });
    });
    const notified: unknown[] = [];
    setUnauthorizedHandler(() => notified.push(true));

    const ok = await apiRequestRaw("/scans/x/report?format=csv");
    expect(ok.status).toBe(200);
    expect(notified).toEqual([]);

    const denied = await apiRequestRaw("/scans/y/report?format=csv");
    expect(denied.status).toBe(401);
    expect(notified).toHaveLength(1);
  });
});

describe("apiRequest timeout and transport failures", () => {
  it("throws a TIMEOUT ApiError when the request exceeds timeoutMs", async () => {
    installFetch(async (_url: unknown, init: unknown) => {
      const signal = (init as RequestInit).signal as AbortSignal | undefined;
      expect(signal).toBeDefined();
      // Hang until aborted, like a stalled backend.
      await new Promise<void>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
      throw new Error("unreachable");
    });

    const err = await apiRequest("/conversations", { timeoutMs: 20 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("TIMEOUT");
    expect((err as ApiError).status).toBe(0);
  });

  it("throws a NETWORK_ERROR ApiError when fetch itself fails", async () => {
    installFetch(async () => {
      throw new TypeError("Failed to fetch");
    });

    const err = await apiRequest("/conversations").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("NETWORK_ERROR");
  });

  it("throws an ABORTED ApiError when the external signal fires", async () => {
    installFetch(async (_url: unknown, init: unknown) => {
      const signal = (init as RequestInit).signal as AbortSignal | undefined;
      await new Promise<void>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
      throw new Error("unreachable");
    });
    const controller = new AbortController();

    const pending = apiRequest("/conversations", { signal: controller.signal }).catch(
      (e: unknown) => e,
    );
    controller.abort();
    const err = await pending;
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("ABORTED");
  });

  it("passes through without a signal when no timeout or signal is given", async () => {
    let seenSignal: unknown = "not-captured";
    installFetch(async (_url: unknown, init: unknown) => {
      seenSignal = (init as RequestInit).signal;
      return jsonResponse({ ok: true }, 200);
    });

    await apiRequest("/targets");
    expect(seenSignal).toBeUndefined();
  });
});
