/**
 * Authenticated app shell — top nav + content outlet.
 *
 * The Phase 0 dashboard was a single page; this layout is the entry
 * point to the four MVP surfaces (overview, targets, scans, scan
 * detail) wired up as the backend reached feature-completeness.
 */

import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext";

export function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-brand">
          <NavLink to="/dashboard" className="brand-link">
            SentinelGPT
          </NavLink>
          <nav className="app-nav" aria-label="Primary">
            <NavLink to="/dashboard" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              Overview
            </NavLink>
            <NavLink to="/targets" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              Targets
            </NavLink>
            <NavLink to="/scans" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              Scans
            </NavLink>
            <NavLink to="/organizations" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              Organizations
            </NavLink>
            <NavLink to="/conversations" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              AI analyst
            </NavLink>
            <NavLink to="/audit-log" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              Audit log
            </NavLink>
          </nav>
        </div>
        <div className="app-session">
          <span className="user-email">{user?.email}</span>
          <button type="button" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}
