import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "./AuthContext";

/** Route guard: unauthenticated visitors never reach protected surfaces. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  if (user === null) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}
