/**
 * Scans page — list / create scan (SRS Ch5 §6).
 *
 * The dashboard lists every scan the user has initiated. Creating a new
 * scan is allowed only against a target with a CONFIRMED attestation;
 * the server returns 403 ATTESTATION_NOT_CONFIRMED otherwise and the UI
 * surfaces the message instead of attempting to enqueue.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import { formatDateTime } from "../../../shared/format";
import { statusPillClass } from "../../../shared/scanStatus";
import { isAttested } from "../../../shared/attestations";
import {
  type Attestation,
  type Target,
} from "../../targets/api/targetsApi";
import { loadTargetsWithAttestations } from "../../targets/api/targetsData";
import { createScan, listScans, type Scan, type ScanProfile } from "../api/scansApi";

export function ScansPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const initialTargetId = params.get("targetId") ?? "";

  const [scans, setScans] = useState<Scan[] | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [attestations, setAttestations] = useState<Record<string, Attestation[]>>({});
  const [targetId, setTargetId] = useState(initialTargetId);
  const [profile, setProfile] = useState<ScanProfile>("quick-check");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      // Targets + attestations come from the shared cached loader: mounting
      // Targets → Scans reuses rows instead of refetching the fan-out.
      const [rows, targetData] = await Promise.all([
        listScans({ limit: 100 }),
        loadTargetsWithAttestations(),
      ]);
      setScans(rows);
      setTargets(targetData.targets);
      setAttestations(targetData.attestations);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load scans.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const attestedTargets = useMemo(
    () =>
      targets.filter(
        (t) => !t.isArchived && isAttested(attestations[t.id] ?? []),
      ),
    [targets, attestations],
  );

  useEffect(() => {
    if (targetId === "" && attestedTargets.length > 0) {
      setTargetId(attestedTargets[0].id);
    }
  }, [attestedTargets, targetId]);

  async function handleCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (targetId === "") {
      setError("Select a target to scan.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await createScan({ targetId, scanProfile: profile });
      await refresh();
      // Client-side navigation into the new scan so the user can watch it
      // progress (stays inside the SPA: no full-page reload, auth context
      // and in-flight state are preserved).
      navigate(`/scans/${created.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to create scan.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page">
      <header className="page-header">
        <h2>Scans</h2>
        <p className="page-subtitle">
          Each scan runs the secure scanning chain in the background. Open a scan to see its
          findings and report.
        </p>
      </header>

      <form className="card form-row" onSubmit={handleCreate}>
        <div className="field">
          <label htmlFor="scan-target">Attested target</label>
          <select
            id="scan-target"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            required
          >
            {attestedTargets.length === 0 && <option value="">— no attested targets —</option>}
            {attestedTargets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.hostname}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="scan-profile">Profile</label>
          <select
            id="scan-profile"
            value={profile}
            onChange={(e) => setProfile(e.target.value as ScanProfile)}
          >
            <option value="quick-check">quick-check</option>
            <option value="standard">standard</option>
            <option value="full-assessment">full-assessment</option>
          </select>
        </div>
        <div className="field field-action">
          <button type="submit" disabled={busy || attestedTargets.length === 0}>
            {busy ? "Queuing…" : "Queue scan"}
          </button>
        </div>
        {attestedTargets.length === 0 && (
          <p className="hint full-row">
            <Link to="/targets">Self-attest a target</Link> before queuing a scan.
          </p>
        )}
        {error && (
          <p className="error full-row" role="alert">
            {error}
          </p>
        )}
      </form>

      {scans === null && <p className="muted">Loading scans…</p>}
      {scans !== null && scans.length === 0 && (
        <p className="muted">No scans yet — queue one above.</p>
      )}

      {scans !== null && scans.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Profile</th>
              <th>Queued</th>
              <th>Started</th>
              <th>Completed</th>
              <th className="actions-col">Open</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>
                  <span className={statusPillClass(s.status)}>{s.status}</span>
                </td>
                <td className="mono small">{s.scanProfile}</td>
                <td className="small">{formatDateTime(s.queuedAt)}</td>
                <td className="small">{formatDateTime(s.startedAt)}</td>
                <td className="small">{formatDateTime(s.completedAt)}</td>
                <td className="actions-col">
                  <Link className="link-button" to={`/scans/${s.id}`}>
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
