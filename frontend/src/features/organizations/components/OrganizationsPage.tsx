/**
 * Organizations page (SRS Chapter 5, Section 3).
 *
 * The backend exposes single-organization lookup (`GET /organizations/{id}`)
 * and member-management endpoints, but no list endpoint today. The page
 * therefore lets the operator:
 *   1. create a new organization (creator becomes ADMIN), or
 *   2. open an organization by id (the request itself acts as a tenant-
 *      isolation check — the backend returns 404 for non-visible rows).
 *
 * Once an organization is loaded, the page lists its members and offers
 * ADMIN-only actions (add / change role / remove) when the backend has
 * confirmed the requester is an ADMIN. The frontend never invents
 * authorization: a 403 from the backend surfaces verbatim.
 */

import { useCallback, useState } from "react";
import { ApiError } from "../../../services/apiClient";
import { formatDateTime } from "../../../shared/format";
import {
  addMember,
  changeMemberRole,
  createOrganization,
  getOrganization,
  listMembers,
  removeMember,
  type Membership,
  type Organization,
  type OrganizationRole,
} from "../api/organizationsApi";

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; organization: Organization; members: Membership[] }
  | { kind: "not-found" }
  | { kind: "error"; message: string };

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function OrganizationsPage() {
  const [state, setState] = useState<LoadState>({ kind: "idle" });
  const [createName, setCreateName] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [openId, setOpenId] = useState("");
  const [openBusy, setOpenBusy] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [memberError, setMemberError] = useState<string | null>(null);

  const loadOrganization = useCallback(async (orgId: string) => {
    setState({ kind: "loading" });
    setMemberError(null);
    try {
      const [organization, members] = await Promise.all([
        getOrganization(orgId),
        listMembers(orgId).catch(() => [] as Membership[]),
      ]);
      setState({ kind: "ready", organization, members });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setState({ kind: "not-found" });
        return;
      }
      setState({
        kind: "error",
        message:
          err instanceof ApiError ? err.message : "Unable to load organization.",
      });
    }
  }, []);

  async function handleCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (createName.trim() === "") {
      setCreateError("Enter an organization name.");
      return;
    }
    setCreateBusy(true);
    setCreateError(null);
    try {
      const created = await createOrganization({ name: createName });
      setCreateName("");
      await loadOrganization(created.id);
    } catch (err) {
      setCreateError(
        err instanceof ApiError ? err.message : "Unable to create organization.",
      );
    } finally {
      setCreateBusy(false);
    }
  }

  async function handleOpen(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = openId.trim();
    if (trimmed === "") {
      setOpenError("Enter an organization id.");
      return;
    }
    if (!UUID_PATTERN.test(trimmed)) {
      setOpenError("Organization id must be a UUID.");
      return;
    }
    setOpenBusy(true);
    setOpenError(null);
    try {
      await loadOrganization(trimmed);
    } finally {
      setOpenBusy(false);
    }
  }

  async function handleAddMember(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (state.kind !== "ready") return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const userId = String(data.get("userId") ?? "").trim();
    const role = String(data.get("role") ?? "MEMBER") as OrganizationRole;
    if (userId === "") {
      setMemberError("Enter a user id.");
      return;
    }
    if (!UUID_PATTERN.test(userId)) {
      setMemberError("User id must be a UUID.");
      return;
    }
    if (role !== "ADMIN" && role !== "MEMBER") {
      setMemberError("Role must be ADMIN or MEMBER.");
      return;
    }
    setBusyAction(`add:${userId}`);
    setMemberError(null);
    try {
      await addMember(state.organization.id, { userId, role });
      form.reset();
      await loadOrganization(state.organization.id);
    } catch (err) {
      setMemberError(
        err instanceof ApiError ? err.message : "Unable to add member.",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleChangeRole(member: Membership, role: OrganizationRole) {
    if (state.kind !== "ready") return;
    if (member.role === role) return;
    setBusyAction(`role:${member.id}`);
    setMemberError(null);
    try {
      await changeMemberRole(state.organization.id, member.userId, { role });
      await loadOrganization(state.organization.id);
    } catch (err) {
      setMemberError(
        err instanceof ApiError ? err.message : "Unable to change role.",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRemove(member: Membership) {
    if (state.kind !== "ready") return;
    if (!window.confirm(`Remove member ${member.userId}?`)) return;
    setBusyAction(`remove:${member.id}`);
    setMemberError(null);
    try {
      await removeMember(state.organization.id, member.userId);
      await loadOrganization(state.organization.id);
    } catch (err) {
      setMemberError(
        err instanceof ApiError ? err.message : "Unable to remove member.",
      );
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h2>Organizations</h2>
          <p className="page-subtitle">
            Create organizations and manage membership. ADMIN actions
            (add, change role, remove) require backend confirmation — a
            <code> 403 </code>
            response is surfaced verbatim.
          </p>
        </div>
      </header>

      <div className="card form-row">
        <form onSubmit={handleCreate} className="form-row-inner">
          <div className="field">
            <label htmlFor="org-name">Create organization</label>
            <input
              id="org-name"
              type="text"
              required
              minLength={1}
              maxLength={255}
              value={createName}
              placeholder="Acme Security"
              onChange={(e) => setCreateName(e.target.value)}
            />
          </div>
          <div className="field field-action">
            <button type="submit" disabled={createBusy}>
              {createBusy ? "Creating…" : "Create"}
            </button>
          </div>
          {createError && (
            <p className="error full-row" role="alert">
              {createError}
            </p>
          )}
        </form>
      </div>

      <div className="card form-row">
        <form onSubmit={handleOpen} className="form-row-inner">
          <div className="field">
            <label htmlFor="org-id">Open by id</label>
            <input
              id="org-id"
              type="text"
              required
              value={openId}
              placeholder="00000000-0000-0000-0000-000000000000"
              onChange={(e) => setOpenId(e.target.value)}
            />
          </div>
          <div className="field field-action">
            <button type="submit" disabled={openBusy}>
              {openBusy ? "Opening…" : "Open"}
            </button>
          </div>
          {openError && (
            <p className="error full-row" role="alert">
              {openError}
            </p>
          )}
        </form>
      </div>

      {state.kind === "loading" && <p className="muted">Loading organization…</p>}

      {state.kind === "not-found" && (
        <p className="error" role="alert">
          Organization not found.
        </p>
      )}

      {state.kind === "error" && (
        <p className="error" role="alert">
          {state.message}
        </p>
      )}

      {state.kind === "ready" && (
        <OrganizationPanel
          organization={state.organization}
          members={state.members}
          busyAction={busyAction}
          memberError={memberError}
          onAdd={handleAddMember}
          onChangeRole={handleChangeRole}
          onRemove={handleRemove}
        />
      )}
    </section>
  );
}

function OrganizationPanel({
  organization,
  members,
  busyAction,
  memberError,
  onAdd,
  onChangeRole,
  onRemove,
}: {
  organization: Organization;
  members: Membership[];
  busyAction: string | null;
  memberError: string | null;
  onAdd: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  onChangeRole: (member: Membership, role: OrganizationRole) => Promise<void>;
  onRemove: (member: Membership) => Promise<void>;
}) {
  // Key the form by organization so switching orgs resets its inputs; no
  // extra render pass needed.
  return (
    <>
      <div className="card metadata">
        <div>
          <span className="meta-label">Name</span>
          <span>{organization.name}</span>
        </div>
        <div>
          <span className="meta-label">Organization id</span>
          <span className="mono">{organization.id}</span>
        </div>
        <div>
          <span className="meta-label">Created</span>
          <span className="small">{formatDateTime(organization.createdAt)}</span>
        </div>
      </div>

      <div className="card">
        <h3>Add member</h3>
        <form onSubmit={onAdd} className="form-row-inner" key={organization.id}>
          <div className="field">
            <label htmlFor="member-userId">User id (UUID)</label>
            <input
              id="member-userId"
              name="userId"
              type="text"
              required
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </div>
          <div className="field">
            <label htmlFor="member-role">Role</label>
            <select id="member-role" name="role" defaultValue="MEMBER">
              <option value="MEMBER">MEMBER</option>
              <option value="ADMIN">ADMIN</option>
            </select>
          </div>
          <div className="field field-action">
            <button
              type="submit"
              disabled={busyAction !== null && busyAction.startsWith("add:")}
            >
              {busyAction !== null && busyAction.startsWith("add:")
                ? "Adding…"
                : "Add member"}
            </button>
          </div>
          {memberError && (
            <p className="error full-row" role="alert">
              {memberError}
            </p>
          )}
        </form>
      </div>

      <div className="card">
        <h3>Members</h3>
        {members.length === 0 ? (
          <p className="muted">No members yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>User id</th>
                <th>Role</th>
                <th>Joined</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {members.map((member) => {
                const roleBusy = busyAction === `role:${member.id}`;
                const removeBusy = busyAction === `remove:${member.id}`;
                return (
                  <tr key={member.id}>
                    <td className="mono small">{member.userId}</td>
                    <td>
                      <span
                        className={
                          member.role === "ADMIN" ? "pill pill-info" : "pill pill-muted"
                        }
                      >
                        {member.role}
                      </span>
                    </td>
                    <td className="small">{formatDateTime(member.createdAt)}</td>
                    <td className="actions-col">
                      <button
                        type="button"
                        className="link-button"
                        disabled={busyAction !== null}
                        onClick={() =>
                          onChangeRole(
                            member,
                            member.role === "ADMIN" ? "MEMBER" : "ADMIN",
                          )
                        }
                      >
                        {roleBusy
                          ? "Working…"
                          : member.role === "ADMIN"
                            ? "Demote to MEMBER"
                            : "Promote to ADMIN"}
                      </button>
                      <button
                        type="button"
                        className="link-button danger"
                        disabled={busyAction !== null}
                        onClick={() => onRemove(member)}
                      >
                        {removeBusy ? "Removing…" : "Remove"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}