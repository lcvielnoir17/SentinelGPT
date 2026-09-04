/**
 * Canonical shared helpers: status pills, formatting, attestation validity.
 *
 * Pins the exact mappings/formatting the pages relied on when inlined, so
 * the consolidation cannot silently change rendered output.
 */

import { describe, expect, it } from "vitest";
import { isAttested } from "./attestations";
import { formatDateTime, truncate } from "./format";
import { statusPillClass } from "./scanStatus";
import type { Attestation } from "../features/targets/api/targetsApi";

describe("statusPillClass", () => {
  it("maps every known scan status", () => {
    expect(statusPillClass("REPORT_READY")).toBe("pill pill-ok");
    expect(statusPillClass("REPORT_READY_DEGRADED")).toBe("pill pill-warn");
    expect(statusPillClass("REJECTED")).toBe("pill pill-bad");
    expect(statusPillClass("CANCELLED")).toBe("pill pill-bad");
    expect(statusPillClass("RUNNING")).toBe("pill pill-info");
    expect(statusPillClass("SCAN_COMPLETE")).toBe("pill pill-info");
    expect(statusPillClass("AI_ANALYSIS")).toBe("pill pill-info");
    expect(statusPillClass("PARTIALLY_COMPLETE")).toBe("pill pill-info");
    expect(statusPillClass("QUEUED")).toBe("pill pill-muted");
  });

  it("falls back to muted for unknown statuses", () => {
    expect(statusPillClass("SOMETHING_NEW")).toBe("pill pill-muted");
  });
});

describe("formatDateTime", () => {
  it("formats ISO timestamps via the locale", () => {
    expect(formatDateTime("2026-09-04T10:00:00Z")).toBe(
      new Date("2026-09-04T10:00:00Z").toLocaleString(),
    );
  });

  it("renders the em-dash placeholder for missing dates", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime(undefined)).toBe("—");
    expect(formatDateTime("")).toBe("—");
  });
});

describe("truncate", () => {
  it("passes short values through and ellipsizes long ones", () => {
    expect(truncate("abc", 12)).toBe("abc");
    expect(truncate("abcdefghijklm", 12)).toBe("abcdefghijkl…");
  });
});

function attestation(overrides: Partial<Attestation> = {}): Attestation {
  return {
    id: "a1",
    targetId: "t1",
    method: "SELF_ATTESTATION",
    status: "CONFIRMED",
    expiresAt: null,
    evidenceFileRef: null,
    revokedAt: null,
    revokedReason: null,
    createdAt: "2026-09-04T10:00:00Z",
    ...overrides,
  };
}

describe("isAttested", () => {
  it("accepts confirmed unexpiring attestations", () => {
    expect(isAttested([attestation()])).toBe(true);
  });

  it("accepts unexpired attestations and rejects expired ones", () => {
    expect(isAttested([attestation({ expiresAt: "2999-01-01T00:00:00Z" })])).toBe(true);
    expect(isAttested([attestation({ expiresAt: "2000-01-01T00:00:00Z" })])).toBe(false);
  });

  it("rejects non-confirmed and empty sets", () => {
    expect(isAttested([attestation({ status: "PENDING_ATTESTATION" })])).toBe(false);
    expect(isAttested([])).toBe(false);
  });
});
