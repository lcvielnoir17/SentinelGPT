/**
 * Audit log page (SRS Chapter 5, Section 12).
 *
 * The page exposes two views selected by the `?entry=<id>` search param:
 *   /audit-log                → list of visible audit entries (newest first)
 *   /audit-log?entry=<id>     → detail view for one entry
 *
 * Visibility is enforced entirely by the backend (fail-closed per
 * AuditService._visible_to). The frontend never invents cross-tenant
 * filters; a 404 from `getAuditEntry` is surfaced as a generic
 * "not found" so an unauthorized entry's existence cannot be inferred.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import { formatDateTime, truncate } from "../../../shared/format";
import {
  getAuditEntry,
  listAuditEntries,
  type AuditEntry,
} from "../api/auditLogApi";

const NOT_FOUND_MESSAGE = "Audit entry not found.";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; entries: AuditEntry[] }
  | { kind: "error"; message: string };

type DetailLoadState =
  | { kind: "loading" }
  | { kind: "ready"; entry: AuditEntry }
  | { kind: "not-found" }
  | { kind: "error"; message: string };

/**
 * Compact, safe rendering of an entry's metadata blob.
 *
 * The backend may place arbitrary JSON under `metadata` (e.g. scan
 * lifecycle from/to codes, attestation method codes, pagination
 * cursors from the meta-audit `AUDIT_LOG_ACCESSED` entries).
 * Stringifying the object keeps the surface predictable and avoids
 * rendering any potential token material that may have leaked into a
 * metadata field by mistake.
 */
function formatMetadata(metadata: Record<string, unknown>): string {
  try {
    return JSON.stringify(metadata, null, 2);
  } catch {
    return "[unserializable metadata]";
  }
}

function summarizeMetadata(metadata: Record<string, unknown>): string {
  const keys = Object.keys(metadata);
  if (keys.length === 0) return "—";
  return keys.slice(0, 3).join(", ") + (keys.length > 3 ? ", …" : "");
}

export function AuditLogPage() {
  const [params, setParams] = useSearchParams();
  const selectedId = params.get("entry");

  if (selectedId !== null && selectedId !== "") {
    return <AuditEntryDetail entryId={selectedId} onBack={() => setParams({})} />;
  }
  return <AuditEntryList onSelectedId={(id) => setParams({ entry: id })} />;
}

function AuditEntryList({ onSelectedId }: { onSelectedId: (id: string) => void }) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  const refresh = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const rows = await listAuditEntries({ limit: 200 });
      setState({ kind: "ready", entries: rows });
    } catch (err) {
      setState({
        kind: "error",
        message: err instanceof ApiError ? err.message : "Unable to load audit log.",
      });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h2>Audit log</h2>
          <p className="page-subtitle">
            Records of actions you have taken or that the platform has recorded
            against resources you own. Entries from other tenants are never
            returned.
          </p>
        </div>
      </header>

      {state.kind === "loading" && <p className="muted">Loading audit log…</p>}

      {state.kind === "error" && (
        <p className="error" role="alert">
          {state.message}
        </p>
      )}

      {state.kind === "ready" && state.entries.length === 0 && (
        <p className="muted">No audit entries yet.</p>
      )}

      {state.kind === "ready" && state.entries.length > 0 && (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Occurred</th>
                <th>Action</th>
                <th>Entity</th>
                <th>Actor</th>
                <th>Metadata</th>
                <th className="actions-col">Open</th>
              </tr>
            </thead>
            <tbody>
              {state.entries.map((entry) => (
                <tr key={entry.id}>
                  <td className="small">{formatDateTime(entry.occurredAt)}</td>
                  <td className="mono small">{entry.actionCode}</td>
                  <td className="mono small">
                    {entry.entityType}/{truncate(entry.entityId, 12)}
                  </td>
                  <td className="mono small">
                    {entry.actorUserId === null
                      ? "system"
                      : truncate(entry.actorUserId, 12)}
                  </td>
                  <td className="mono small">
                    {summarizeMetadata(entry.metadata)}
                  </td>
                  <td className="actions-col">
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => onSelectedId(entry.id)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function AuditEntryDetail({
  entryId,
  onBack,
}: {
  entryId: string;
  onBack: () => void;
}) {
  const [state, setState] = useState<DetailLoadState>({ kind: "loading" });

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const entry = await getAuditEntry(entryId);
      setState({ kind: "ready", entry });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setState({ kind: "not-found" });
        return;
      }
      setState({
        kind: "error",
        message:
          err instanceof ApiError ? err.message : "Unable to load audit entry.",
      });
    }
  }, [entryId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h2>Audit entry</h2>
          <p className="page-subtitle mono small">{entryId}</p>
        </div>
        <div className="page-actions">
          <button type="button" className="link-button" onClick={onBack}>
            ← All entries
          </button>
        </div>
      </header>

      {state.kind === "loading" && <p className="muted">Loading entry…</p>}

      {state.kind === "not-found" && (
        <p className="error" role="alert">
          {NOT_FOUND_MESSAGE}
        </p>
      )}

      {state.kind === "error" && (
        <p className="error" role="alert">
          {state.message}
        </p>
      )}

      {state.kind === "ready" && <AuditEntryDetailCard entry={state.entry} />}
    </section>
  );
}

function AuditEntryDetailCard({ entry }: { entry: AuditEntry }) {
  const rows = useMemo(
    () => [
      { label: "Occurred at", value: formatDateTime(entry.occurredAt) },
      { label: "Action", value: entry.actionCode, mono: true },
      { label: "Entity type", value: entry.entityType, mono: true },
      { label: "Entity id", value: entry.entityId, mono: true },
      {
        label: "Actor",
        value: entry.actorUserId === null ? "system" : entry.actorUserId,
        mono: true,
      },
    ],
    [entry],
  );
  return (
    <>
      <div className="card metadata">
        {rows.map((row) => (
          <div key={row.label}>
            <span className="meta-label">{row.label}</span>
            <span className={row.mono ? "mono" : undefined}>{row.value}</span>
          </div>
        ))}
      </div>
      <div className="card">
        <h3>Metadata</h3>
        <pre className="evidence">{formatMetadata(entry.metadata)}</pre>
      </div>
    </>
  );
}