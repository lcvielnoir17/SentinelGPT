/**
 * Overview / dashboard summary (SRS Ch7 §5 + Ch15 §4 "raw findings" view).
 *
 * Surfaces a count of targets and scans, plus the most recent scans
 * (with their live status) so a returning operator can see at a glance
 * whether anything is still in flight. The full dashboard with charts
 * and cross-scan comparison waits for Phase 4 in the SRS.
 */

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../services/apiClient";
import { formatDateTime } from "../../shared/format";
import { statusPillClass } from "../../shared/scanStatus";
import { type Target } from "../targets/api/targetsApi";
import { loadTargets } from "../targets/api/targetsData";
import { listScans, type Scan } from "../scans/api/scansApi";

export function DashboardPage() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // One page sized for the recent-scans table; the stat cards derive
        // from the same rows so the dashboard costs a single scans request.
        // (Previously limit=5, which also misreported "Total scans" as ≤5.)
        // Targets come from the shared cache (no extra request after visiting
        // Targets/Scans).
        const [t, s] = await Promise.all([loadTargets(), listScans({ limit: 100 })]);
        if (cancelled) return;
        setTargets(t);
        setScans(s);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Unable to load dashboard.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const activeTargets = targets === null ? null : targets.filter((t) => !t.isArchived).length;
  const inFlight =
    scans === null ? null : scans.filter((s) => s.status === "QUEUED" || s.status === "RUNNING").length;

  return (
    <section className="page">
      <header className="page-header">
        <h2>Overview</h2>
        <p className="page-subtitle">
          Register an authorized target, attest to your authorization, and queue scans against it.
          Findings and reports will appear as the platform runs.
        </p>
      </header>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <div className="stat-row">
        <div className="card stat">
          <span className="meta-label">Active targets</span>
          <span className="stat-value">{activeTargets ?? "—"}</span>
          <Link className="link-button" to="/targets">
            Manage targets
          </Link>
        </div>
        <div className="card stat">
          <span className="meta-label">In-flight scans</span>
          <span className="stat-value">{inFlight ?? "—"}</span>
          <Link className="link-button" to="/scans">
            Manage scans
          </Link>
        </div>
        <div className="card stat">
          <span className="meta-label">Recent scans</span>
          <span className="stat-value">{scans === null ? "—" : scans.length}</span>
          <span className="muted small">Most recent {scans?.length ?? 0} shown below</span>
        </div>
      </div>

      <div className="card">
        <h3>Recent scans</h3>
        {scans === null ? (
          <p className="muted">Loading…</p>
        ) : scans.length === 0 ? (
          <p className="muted">No scans yet.</p>
        ) : (
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Status</th>
                <th>Profile</th>
                <th>Queued</th>
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
      </div>
    </section>
  );
}
