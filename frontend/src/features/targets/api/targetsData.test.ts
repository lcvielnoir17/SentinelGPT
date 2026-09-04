/**
 * Shared targets loader: dedup, cache, and fail-open attestation fetching.
 *
 * Protects the consolidation of the ScansPage/TargetsPage fan-out:
 * concurrent loads share one flight, warm cache serves without network,
 * invalidate forces refetch, and a per-target attestation failure degrades
 * to [] for that target instead of failing the whole load.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  invalidateTargetsCache,
  loadTargets,
  loadTargetsWithAttestations,
} from "./targetsData";
import { listAttestations, listTargets } from "./targetsApi";
import type { Target } from "./targetsApi";

vi.mock("./targetsApi", () => ({
  listTargets: vi.fn(),
  listAttestations: vi.fn(),
  createTarget: vi.fn(),
  getTarget: vi.fn(),
  setTargetArchived: vi.fn(),
  createSelfAttestation: vi.fn(),
  listTargetAttestations: vi.fn(),
}));

const mockedListTargets = vi.mocked(listTargets);
const mockedListAttestations = vi.mocked(listAttestations);

function target(id: string): Target {
  return {
    id,
    hostname: `${id}.example.com`,
    url: `https://${id}.example.com/`,
    ownerOrganizationId: null,
    ownerUserId: "user-1",
    isArchived: false,
    createdAt: "2026-09-04T10:00:00Z",
    status: "CONFIRMED",
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  invalidateTargetsCache();
  mockedListTargets.mockResolvedValue({ items: [target("t1"), target("t2")], pageInfo: { nextCursor: null, hasNextPage: false } });
  mockedListAttestations.mockResolvedValue([]);
});

describe("loadTargets", () => {
  it("shares one flight across concurrent callers", async () => {
    const [a, b] = await Promise.all([loadTargets(), loadTargets()]);
    expect(a).toHaveLength(2);
    expect(b).toHaveLength(2);
    expect(mockedListTargets).toHaveBeenCalledTimes(1);
  });

  it("serves warm cache without new requests and refetches after invalidate", async () => {
    await loadTargets();
    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(1);
    invalidateTargetsCache();
    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(2);
  });
});

describe("loadTargetsWithAttestations", () => {
  it("fans out one attestation request per target", async () => {
    const data = await loadTargetsWithAttestations();
    expect(Object.keys(data.attestations).sort()).toEqual(["t1", "t2"]);
    expect(mockedListAttestations).toHaveBeenCalledTimes(2);
  });

  it("degrades a per-target failure to an empty list", async () => {
    mockedListAttestations.mockRejectedValueOnce(new Error("boom"));
    const data = await loadTargetsWithAttestations();
    expect(data.attestations["t1"]).toEqual([]);
    expect(data.attestations["t2"]).toEqual([]);
  });

  it("does not cache degraded snapshots", async () => {
    mockedListAttestations.mockRejectedValueOnce(new Error("boom"));
    await loadTargetsWithAttestations();
    expect(mockedListAttestations).toHaveBeenCalledTimes(2);

    // Next mount refetches instead of serving the degraded snapshot.
    await loadTargetsWithAttestations();
    expect(mockedListAttestations).toHaveBeenCalledTimes(4);
  });

  it("rejects the whole load when the target list fails", async () => {
    mockedListTargets.mockRejectedValueOnce(new Error("down"));
    await expect(loadTargetsWithAttestations()).rejects.toThrow("down");
  });
});
