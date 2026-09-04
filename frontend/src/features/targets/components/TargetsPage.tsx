/**
 * Targets page — list / create / self-attest / archive (SRS Ch5 §4, §5).
 *
 * Two-step flow to add a scannable target:
 *   1. POST /targets          → status = PENDING_ATTESTATION
 *   2. POST .../attestations  → status = CONFIRMED  (enables scan creation)
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import { formatDateTime } from "../../../shared/format";
import { isAttested } from "../../../shared/attestations";
import {
  createSelfAttestation,
  createTarget,
  setTargetArchived,
  type Attestation,
  type Target,
} from "../api/targetsApi";
import { useTargetsWithAttestations } from "../api/targetsData";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; targets: Target[] }
  | { kind: "error"; message: string };

export function TargetsPage() {
  const {
    data,
    error: loadError,
    refresh: reloadTargets,
  } = useTargetsWithAttestations();
  const [hostname, setHostname] = useState("");
  const [url, setUrl] = useState("https://");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Preserve the screen's loading/error/ready contract; rows now come from
  // the shared cached loader instead of a per-mount fan-out.
  const state: LoadState =
    data !== null
      ? { kind: "ready", targets: data.targets }
      : loadError !== null
        ? { kind: "error", message: loadError }
        : { kind: "loading" };
  const attestations: Record<string, Attestation[]> = data?.attestations ?? {};

  async function handleCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setActionError(null);
    try {
      await createTarget({ hostname: hostname.trim(), url: url.trim() });
      setHostname("");
      setUrl("https://");
      await reloadTargets();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Unable to create target.");
    } finally {
      setBusy(false);
    }
  }

  async function handleAttest(targetId: string) {
    setBusy(true);
    setActionError(null);
    try {
      await createSelfAttestation(targetId);
      await reloadTargets();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Unable to submit attestation.");
    } finally {
      setBusy(false);
    }
  }

  async function handleArchive(target: Target) {
    setBusy(true);
    setActionError(null);
    try {
      await setTargetArchived(target.id, !target.isArchived);
      await reloadTargets();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Unable to update target.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page">
      <header className="page-header">
        <h2>Targets</h2>
        <p className="page-subtitle">
          Authorize a hostname for scanning. A CONFIRMED self-attestation is required before any
          scan can be queued against the target.
        </p>
      </header>

      <form className="card form-row" onSubmit={handleCreate}>
        <div className="field">
          <label htmlFor="t-hostname">Hostname</label>
          <input
            id="t-hostname"
            type="text"
            required
            value={hostname}
            placeholder="example.com"
            onChange={(e) => setHostname(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="t-url">URL</label>
          <input
            id="t-url"
            type="url"
            required
            value={url}
            placeholder="https://example.com/health"
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>
        <div className="field field-action">
          <button type="submit" disabled={busy}>
            {busy ? "Working…" : "Add target"}
          </button>
        </div>
        {actionError && (
          <p className="error" role="alert">
            {actionError}
          </p>
        )}
      </form>

      {state.kind === "loading" && <p className="muted">Loading targets…</p>}
      {state.kind === "error" && (
        <p className="error" role="alert">
          {state.message}
        </p>
      )}

      {state.kind === "ready" && state.targets.length === 0 && (
        <p className="muted">No targets yet — register one above to begin.</p>
      )}

      {state.kind === "ready" && state.targets.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>URL</th>
              <th>Attestation</th>
              <th>Archived</th>
              <th>Created</th>
              <th className="actions-col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {state.targets.map((t) => {
              const attested = isAttested(attestations[t.id] ?? []);
              return (
                <tr key={t.id} className={t.isArchived ? "row-archived" : undefined}>
                  <td className="mono">{t.hostname}</td>
                  <td className="mono small">{t.url}</td>
                  <td>
                    {attested ? (
                      <span className="pill pill-ok">CONFIRMED</span>
                    ) : (
                      <span className="pill pill-warn">PENDING</span>
                    )}
                  </td>
                  <td>{t.isArchived ? "Yes" : "No"}</td>
                  <td className="small">{formatDateTime(t.createdAt)}</td>
                  <td className="actions-col">
                    {!attested && !t.isArchived && (
                      <button
                        type="button"
                        className="link-button"
                        disabled={busy}
                        onClick={() => handleAttest(t.id)}
                      >
                        Self-attest
                      </button>
                    )}
                    {attested && !t.isArchived && (
                      <Link className="link-button" to={`/scans?targetId=${t.id}`}>
                        Scan
                      </Link>
                    )}
                    <button
                      type="button"
                      className="link-button"
                      disabled={busy}
                      onClick={() => handleArchive(t)}
                    >
                      {t.isArchived ? "Unarchive" : "Archive"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
