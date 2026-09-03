/**
 * Scan detail page (SRS Ch5 §6 + Ch9 + Ch10 §4).
 *
 * Surfaces the live scan status, deterministic findings, the per-finding
 * AI explanation (validated or fallback), JSON/CSV report download, the
 * rescan action, and a comparison panel for two scans of the same target.
 *
 * The status refresh interval is a simple poll: the worker writes
 * status changes back to the database so a few-seconds poll is enough.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import { downloadScanReport } from "../../reports/reportsApi";
import { ConversationPanel } from "../../conversations/components/ConversationPanel";
import {
  cancelScan,
  compareScans,
  getAssessment,
  getScan,
  getFindingExplanation,
  listFindings,
  listScans,
  rescanScan,
  type Assessment,
  type CompareResponse,
  type Finding,
  type FindingCompareItem,
  type FindingExplanation,
  type Scan,
} from "../api/scansApi";

const TERMINAL_STATUSES: Scan["status"][] = [
  "REPORT_READY",
  "REPORT_READY_DEGRADED",
  "REJECTED",
  "CANCELLED",
];

/**
 * Scan statuses for which a rescan button is exposed in the UI.
 *
 * The backend's `rescan_scan` service reuses the original scan's
 * target + profile + attestation and queues a new scan — it does NOT
 * re-check the parent's status. UI-side, the operator-meaningful
 * "Rescan" workflow is "I have a finished scan, run it again", so we
 * only show the action on completed scans. The backend remains
 * authoritative: a stale UI state where the user clicks "Rescan" on a
 * scan that just transitioned is still safely rejected by the
 * attestation gate.
 */
const RESCAN_ELIGIBLE_STATUSES: Scan["status"][] = [
  "REPORT_READY",
  "REPORT_READY_DEGRADED",
];

function statusPillClass(status: Scan["status"]): string {
  switch (status) {
    case "REPORT_READY":
      return "pill pill-ok";
    case "REPORT_READY_DEGRADED":
      return "pill pill-warn";
    case "REJECTED":
    case "CANCELLED":
      return "pill pill-bad";
    case "RUNNING":
    case "SCAN_COMPLETE":
    case "AI_ANALYSIS":
    case "PARTIALLY_COMPLETE":
      return "pill pill-info";
    case "QUEUED":
    default:
      return "pill pill-muted";
  }
}

export function ScanDetailPage() {
  const { scanId = "" } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [explanations, setExplanations] = useState<Record<string, FindingExplanation>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rescanBusy, setRescanBusy] = useState(false);
  const [rescanError, setRescanError] = useState<string | null>(null);
  const [rescanLink, setRescanLink] = useState<string | null>(null);
  // Which finding's analyst conversation is open (null = all closed).
  const [chatFindingId, setChatFindingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const next = await getScan(scanId);
      setScan(next);
      if (TERMINAL_STATUSES.includes(next.status)) {
        const [rows, assessmentRow] = await Promise.all([
          listFindings(scanId).catch(() => [] as Finding[]),
          getAssessment(scanId).catch(() => null),
        ]);
        setFindings(rows);
        setAssessment(assessmentRow);
        const explanationsAccumulator: Record<string, FindingExplanation> = {};
        await Promise.all(
          rows.map(async (f) => {
            try {
              explanationsAccumulator[f.id] = await getFindingExplanation(scanId, f.id);
            } catch {
              explanationsAccumulator[f.id] = {
                available: false,
                validationStatus: "FALLBACK_USED",
                fallbackReason: "request_failed",
              };
            }
          }),
        );
        setExplanations(explanationsAccumulator);
      } else {
        setFindings([]);
        setAssessment(null);
        setExplanations({});
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load scan.");
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Poll while the scan is still running.
  useEffect(() => {
    if (scan === null) return;
    if (TERMINAL_STATUSES.includes(scan.status)) return;
    const handle = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(handle);
  }, [scan, load]);

  async function handleCancel() {
    setBusy(true);
    setError(null);
    try {
      await cancelScan(scanId);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to cancel scan.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(format: "json" | "csv") {
    setBusy(true);
    setError(null);
    try {
      const { blob, filename } = await downloadScanReport(scanId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to download report.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRescan() {
    if (scan === null) return;
    setRescanBusy(true);
    setRescanError(null);
    setRescanLink(null);
    try {
      const newScan = await rescanScan(scan.id);
      setRescanLink(newScan.id);
    } catch (err) {
      setRescanError(
        err instanceof ApiError ? err.message : "Unable to queue rescan.",
      );
    } finally {
      setRescanBusy(false);
    }
  }

  if (scan === null && error === null) {
    return <p className="muted">Loading scan…</p>;
  }

  if (scan === null) {
    return (
      <p className="error" role="alert">
        {error}
      </p>
    );
  }

  const cancellable = scan.status === "QUEUED";
  const rescanEligible = RESCAN_ELIGIBLE_STATUSES.includes(scan.status);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h2>
            Scan <span className="mono small">{scan.id}</span>
          </h2>
          <p className="page-subtitle">
            Target <span className="mono">{scan.targetId}</span> · profile{" "}
            <span className="mono">{scan.scanProfile}</span>
          </p>
        </div>
        <div className="page-actions">
          <Link className="link-button" to="/scans">
            ← All scans
          </Link>
          {cancellable && (
            <button type="button" className="link-button danger" disabled={busy} onClick={handleCancel}>
              Cancel
            </button>
          )}
        </div>
      </header>

      <div className="card metadata">
        <div>
          <span className="meta-label">Status</span>
          <span className={statusPillClass(scan.status)}>{scan.status}</span>
        </div>
        <div>
          <span className="meta-label">Queued</span>
          <span>{scan.queuedAt ? new Date(scan.queuedAt).toLocaleString() : "—"}</span>
        </div>
        <div>
          <span className="meta-label">Started</span>
          <span>{scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "—"}</span>
        </div>
        <div>
          <span className="meta-label">Completed</span>
          <span>{scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "—"}</span>
        </div>
      </div>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {rescanEligible && (
        <div className="card">
          <h3>Rescan</h3>
          <p className="muted">
            Queue a new scan against the same target, profile, and authorization
            attestation. The new scan appears under "All scans" with this one as
            its parent.
          </p>
          <div className="button-row">
            <button type="button" disabled={rescanBusy} onClick={handleRescan}>
              {rescanBusy ? "Rescanning…" : "Rescan"}
            </button>
            {rescanLink !== null && (
              <button
                type="button"
                className="link-button"
                onClick={() => navigate(`/scans/${rescanLink}`)}
              >
                Open the new scan →
              </button>
            )}
          </div>
          {rescanError && (
            <p className="error" role="alert">
              {rescanError}
            </p>
          )}
        </div>
      )}

      {TERMINAL_STATUSES.includes(scan.status) && (
        <div className="card report-actions">
          <h3>Report</h3>
          <p className="muted">
            Export the canonical report. Severity and finding lifecycle are preserved exactly
            as the scanner produced them.
          </p>
          <div className="button-row">
            <button type="button" disabled={busy} onClick={() => handleDownload("json")}>
              Download JSON
            </button>
            <button type="button" disabled={busy} onClick={() => handleDownload("csv")}>
              Download CSV
            </button>
          </div>
        </div>
      )}

      {TERMINAL_STATUSES.includes(scan.status) && (
        <div className="card">
          <h3>AI Assessment</h3>
          {assessment === null ? (
            <p className="muted">No assessment recorded.</p>
          ) : !assessment.available ? (
            <p className="muted">
              Assessment not available
              {assessment.failureKind ? ` (${assessment.failureKind})` : ""}. Findings below use
              the deterministic fallback explanation.
            </p>
          ) : (
            <p className="muted">
              Model: <span className="mono">{assessment.model}</span> · provider:{" "}
              <span className="mono">{assessment.provider}</span> · schema{" "}
              <span className="mono">{assessment.promptSchemaVersion}</span>
            </p>
          )}
        </div>
      )}

      <div className="card">
        <h3>Findings</h3>
        {findings === null ? (
          <p className="muted">Loading findings…</p>
        ) : findings.length === 0 ? (
          <p className="muted">
            {TERMINAL_STATUSES.includes(scan.status)
              ? "No findings were produced."
              : "Findings appear after the scan reaches a terminal status."}
          </p>
        ) : (
          <ul className="findings">
            {findings.map((f) => {
              const exp = explanations[f.id];
              const chatOpen = chatFindingId === f.id;
              return (
                <li key={f.id} className="finding">
                  <header className="finding-header">
                    <span className={`pill severity-${f.severity.toLowerCase()}`}>
                      {f.severity}
                    </span>
                    <h4>{f.title}</h4>
                  </header>
                  <p className="finding-meta mono small">location: {f.location}</p>
                  <p>{f.description}</p>
                  <details>
                    <summary>Evidence</summary>
                    <pre className="evidence">{f.evidence}</pre>
                  </details>
                  {f.recommendation && (
                    <p>
                      <strong>Recommendation:</strong> {f.recommendation}
                    </p>
                  )}
                  {exp && (
                    <div className="explanation">
                      <p className="muted small">
                        AI explanation ·{" "}
                        <span
                          className={
                            exp.validationStatus === "validated"
                              ? "pill pill-ok"
                              : "pill pill-warn"
                          }
                        >
                          {exp.validationStatus}
                        </span>
                        {exp.fallbackReason ? ` (reason: ${exp.fallbackReason})` : ""}
                      </p>
                      {exp.explanation && (
                        <pre className="evidence">
                          {JSON.stringify(exp.explanation, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                  <div className="ask-analyst">
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => setChatFindingId(chatOpen ? null : f.id)}
                    >
                      {chatOpen ? "Close analyst" : "Ask SentinelGPT"}
                    </button>
                    {chatOpen && (
                      <ConversationPanel scanId={scanId} findingId={f.id} />
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <ComparePanel currentScan={scan} />
    </section>
  );
}

type CandidateScansState =
  | { kind: "loading" }
  | { kind: "ready"; candidates: Scan[] }
  | { kind: "error"; message: string };

type CompareState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; result: CompareResponse }
  | { kind: "not-found" }
  | { kind: "different-targets" }
  | { kind: "error"; message: string };

function ComparePanel({ currentScan }: { currentScan: Scan }) {
  const [candidates, setCandidates] = useState<CandidateScansState>({ kind: "loading" });
  const [selectedId, setSelectedId] = useState<string>("");
  const [compareState, setCompareState] = useState<CompareState>({ kind: "idle" });
  const [compareBusy, setCompareBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setCandidates({ kind: "loading" });
    listScans({ targetId: currentScan.targetId, limit: 100 })
      .then((rows) => {
        if (cancelled) return;
        // Filter out the current scan — comparing a scan to itself is
        // meaningless and a backend self-compare would surface as 409.
        const filtered = rows.filter((row) => row.id !== currentScan.id);
        setCandidates({ kind: "ready", candidates: filtered });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setCandidates({
          kind: "error",
          message:
            err instanceof ApiError
              ? err.message
              : "Unable to load scans for comparison.",
        });
      });
    return () => {
      cancelled = true;
    };
  }, [currentScan.id, currentScan.targetId]);

  // Reset the compare result whenever the user changes the selection.
  useEffect(() => {
    setCompareState({ kind: "idle" });
  }, [selectedId]);

  const canCompare =
    candidates.kind === "ready" &&
    candidates.candidates.length > 0 &&
    selectedId !== "" &&
    !compareBusy;

  async function handleCompare() {
    if (!canCompare) return;
    setCompareBusy(true);
    setCompareState({ kind: "loading" });
    try {
      const result = await compareScans(currentScan.id, selectedId);
      setCompareState({ kind: "ready", result });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 404) {
          setCompareState({ kind: "not-found" });
        } else if (err.status === 409) {
          setCompareState({ kind: "different-targets" });
        } else {
          setCompareState({ kind: "error", message: err.message });
        }
      } else {
        setCompareState({
          kind: "error",
          message: err instanceof Error ? err.message : "Unable to compare scans.",
        });
      }
    } finally {
      setCompareBusy(false);
    }
  }

  return (
    <div className="card">
      <h3>Compare</h3>
      <p className="muted">
        Diff the finding set of this scan against another scan of the same
        target. Both scans must be visible to you; the backend rejects
        cross-tenant comparisons as 404 (no existence leak).
      </p>

      {candidates.kind === "loading" && (
        <p className="muted">Loading candidate scans…</p>
      )}

      {candidates.kind === "error" && (
        <p className="error" role="alert">
          {candidates.message}
        </p>
      )}

      {candidates.kind === "ready" && candidates.candidates.length === 0 && (
        <p className="muted">No other scans of this target are available to compare.</p>
      )}

      {candidates.kind === "ready" && candidates.candidates.length > 0 && (
        <div className="form-row-inner">
          <div className="field">
            <label htmlFor="compare-against">Compare against</label>
            <select
              id="compare-against"
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
            >
              <option value="">— select a scan —</option>
              {candidates.candidates.map((c) => (
                <option key={c.id} value={c.id}>
                  {formatScanOption(c)}
                </option>
              ))}
            </select>
          </div>
          <div className="field field-action">
            <button type="button" disabled={!canCompare} onClick={handleCompare}>
              {compareBusy ? "Comparing…" : "Compare"}
            </button>
          </div>
        </div>
      )}

      {compareState.kind === "loading" && (
        <p className="muted">Comparing scans…</p>
      )}

      {compareState.kind === "not-found" && (
        <p className="error" role="alert">
          Comparison target not found.
        </p>
      )}

      {compareState.kind === "different-targets" && (
        <p className="error" role="alert">
          Scans do not target the same host — pick another scan.
        </p>
      )}

      {compareState.kind === "error" && (
        <p className="error" role="alert">
          {compareState.message}
        </p>
      )}

      {compareState.kind === "ready" && <CompareResultView result={compareState.result} />}
    </div>
  );
}

function formatScanOption(scan: Scan): string {
  const stamp = scan.completedAt ?? scan.queuedAt ?? scan.createdAt;
  const when = stamp ? new Date(stamp).toLocaleString() : "—";
  return `${scan.status} · ${when} · ${truncate(scan.id, 8)}`;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…`;
}

function CompareResultView({ result }: { result: CompareResponse }) {
  const groups = useMemo(
    () => [
      { key: "new", label: "New", items: result.new, pill: "pill-warn" as const },
      { key: "persistent", label: "Persistent", items: result.persistent, pill: "pill-info" as const },
      { key: "resolved", label: "Resolved", items: result.resolved, pill: "pill-ok" as const },
      { key: "regressed", label: "Regressed", items: result.regressed, pill: "pill-bad" as const },
    ],
    [result],
  );
  const total = groups.reduce((acc, g) => acc + g.items.length, 0);
  if (total === 0) {
    return <p className="muted">No comparison data.</p>;
  }
  return (
    <div className="compare-grid">
      {groups.map((group) => (
        <div key={group.key} className="compare-group">
          <h4>
            <span className={`pill ${group.pill}`}>{group.label}</span>
            <span className="muted small"> · {group.items.length}</span>
          </h4>
          {group.items.length === 0 ? (
            <p className="muted small">No findings in this group.</p>
          ) : (
            <ul className="compare-list">
              {group.items.map((item) => (
                <CompareItemRow key={item.id} item={item} />
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

function CompareItemRow({ item }: { item: FindingCompareItem }) {
  return (
    <li className="compare-item">
      <span className="compare-item-title">{item.title}</span>
      <span className="compare-item-meta mono small">
        fingerprint: {truncate(item.fingerprint, 16)} · id: {truncate(item.id, 8)}
      </span>
    </li>
  );
}
