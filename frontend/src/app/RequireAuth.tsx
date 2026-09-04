import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "./AuthContext";

/**
 * Route guard: unauthenticated visitors never reach protected surfaces.
 *
 * While the session-restore bootstrap probe is in flight, the guard
 * renders a neutral placeholder so a returning user with a valid access
 * cookie is never briefly redirected to /login (which would otherwise
 * flash on every page reload).
 *
 * The attempted URL travels as `state.from` so a successful login returns
 * the user to their deep link instead of always landing on /dashboard.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, bootstrap } = useAuth();
  const location = useLocation();
  if (bootstrap === "pending") {
    return (
      <main className="auth-page">
        <p className="muted" role="status">
          Restoring session…
        </p>
      </main>
    );
  }
  if (user === null) {
    const from = `${location.pathname}${location.search}`;
    return <Navigate to="/login" replace state={{ from }} />;
  }
  return <>{children}</>;
}