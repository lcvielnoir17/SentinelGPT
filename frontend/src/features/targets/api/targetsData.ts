/**
 * Shared targets + attestations loading (ScansPage, TargetsPage, Dashboard).
 *
 * Previously each screen reimplemented the same fan-out: `listTargets()`
 * followed by one `listAttestations(targetId)` per target. This module is
 * the single implementation, with two efficiency properties:
 *
 * 1. In-flight deduplication — concurrent mounters share one promise, so
 *    navigating Targets → Scans issues one target list, not two.
 * 2. A short (30s) cache — back-navigation and re-renders reuse rows
 *    instead of refetching; mutations call `refreshTargetsData()`.
 *
 * Failure semantics are preserved exactly: a `listTargets` failure rejects
 * the whole load (screens show their error state), while a per-target
 * attestation failure degrades to `[]` for that target (fail-open).
 */

import { useCallback, useEffect, useState } from "react";
import { listAttestations, listTargets, type Attestation, type Target } from "./targetsApi";

export interface TargetsData {
  targets: Target[];
  attestations: Record<string, Attestation[]>;
}

const CACHE_TTL_MS = 30_000;

let targetsCache: { at: number; rows: Target[] } | null = null;
let targetsInflight: Promise<Target[]> | null = null;
let fullCache: { at: number; data: TargetsData } | null = null;
let fullInflight: Promise<TargetsData> | null = null;

function fresh(at: number): boolean {
  return Date.now() - at < CACHE_TTL_MS;
}

async function fetchTargets(): Promise<Target[]> {
  const list = await listTargets();
  return list.items;
}

/** Cached target list (Dashboard and everything needing targets only). */
export function loadTargets(): Promise<Target[]> {
  if (targetsCache && fresh(targetsCache.at)) return Promise.resolve(targetsCache.rows);
  if (!targetsInflight) {
    targetsInflight = fetchTargets().then((rows) => {
      targetsCache = { at: Date.now(), rows };
      targetsInflight = null;
      return rows;
    });
    // Share rejections without unhandled-rejection noise; callers still see them.
    targetsInflight.catch(() => {
      targetsInflight = null;
    });
  }
  return targetsInflight;
}

async function fetchFull(): Promise<TargetsData> {
  const targets = await loadTargets();
  const pairs = await Promise.all(
    targets.map((t) =>
      listAttestations(t.id)
        .then((rows) => [t.id, rows] as const)
        .catch(() => [t.id, []] as const),
    ),
  );
  return { targets, attestations: Object.fromEntries(pairs) };
}

/** Cached targets + per-target attestations (ScansPage, TargetsPage). */
export function loadTargetsWithAttestations(): Promise<TargetsData> {
  if (fullCache && fresh(fullCache.at)) return Promise.resolve(fullCache.data);
  if (!fullInflight) {
    fullInflight = fetchFull().then((data) => {
      fullCache = { at: Date.now(), data };
      fullInflight = null;
      return data;
    });
    fullInflight.catch(() => {
      fullInflight = null;
    });
  }
  return fullInflight;
}

/** Drop all cached rows (call after create/attest/archive mutations). */
export function invalidateTargetsCache(): void {
  targetsCache = null;
  fullCache = null;
}

/**
 * React binding for `loadTargetsWithAttestations` with unmount safety and
 * an explicit refresh (invalidate + reload) for mutation handlers.
 */
export function useTargetsWithAttestations(): {
  data: TargetsData | null;
  error: string | null;
  refresh: () => Promise<void>;
} {
  const [data, setData] = useState<TargetsData | null>(() => fullCache?.data ?? null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    invalidateTargetsCache();
    try {
      setData(await loadTargetsWithAttestations());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load targets.");
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    if (data === null) {
      loadTargetsWithAttestations().then(
        (loaded) => {
          if (!cancelled) setData(loaded);
        },
        (err: unknown) => {
          if (!cancelled) setError(err instanceof Error ? err.message : "Unable to load targets.");
        },
      );
    }
    return () => {
      cancelled = true;
    };
    // Mount-only load; refreshes go through `refresh`.
  }, []);

  return { data, error, refresh };
}
