/**
 * Application shell and routing (SRS Chapter 2, Section 4 — src/app/).
 */

import { Navigate, Route, Routes } from "react-router-dom";
import { AuthPage } from "../features/auth/components/AuthPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { RequireAuth } from "./RequireAuth";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<AuthPage />} />
      <Route
        path="/dashboard"
        element={
          <RequireAuth>
            <DashboardPage />
          </RequireAuth>
        }
      />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}
