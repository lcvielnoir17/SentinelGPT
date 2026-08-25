/**
 * Empty authenticated dashboard shell — the Phase 0 exit-criterion surface.
 * Real dashboard content (targets, scans, findings) arrives in later phases.
 */

import { useNavigate } from "react-router-dom";
import { useAuth } from "../../app/AuthContext";

export function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <main className="dashboard">
      <header className="dashboard-header">
        <h1>SentinelGPT</h1>
        <div className="session">
          {/* PHASE 0: in-memory session identity. Phase 1 replaces this with
              HttpOnly-cookie sessions verified server-side (GET /auth/me). */}
          <span>{user?.email}</span>
          <button type="button" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </header>

      <section className="empty-state" aria-label="Dashboard placeholder">
        <h2>Welcome</h2>
        <p>
          Your authenticated dashboard shell is working. Targets, scans,
          findings, and reports will appear here as later phases deliver them.
        </p>
      </section>
    </main>
  );
}
