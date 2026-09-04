/**
 * Canonical attestation-validity predicate.
 *
 * Previously duplicated in ScansPage and TargetsPage. An attestation
 * counts when CONFIRMED and unexpired (null expiry = no expiry).
 */
import type { Attestation } from "../features/targets/api/targetsApi";

export function isAttested(attestations: Attestation[]): boolean {
  return attestations.some(
    (a) => a.status === "CONFIRMED" && (a.expiresAt === null || new Date(a.expiresAt) > new Date()),
  );
}
