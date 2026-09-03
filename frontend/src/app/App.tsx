/**
 * Application shell and routing (SRS Chapter 2, Section 4 — src/app/).
 *
 * Routes:
 *   /login          → AuthPage (public)
 *   /dashboard      → DashboardPage (overview)   — requires auth
 *   /targets        → TargetsPage                — requires auth
 *   /scans          → ScansPage                  — requires auth
 *   /scans/:id      → ScanDetailPage             — requires auth
 *   /organizations  → OrganizationsPage          — requires auth
 *   /conversations  → ConversationsPage          — requires auth
 *   /audit-log      → AuditLogPage               — requires auth
 */

import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./AppLayout";
import { AuthPage } from "../features/auth/components/AuthPage";
import { AuditLogPage } from "../features/audit/components/AuditLogPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { ConversationsPage } from "../features/conversations/components/ConversationsPage";
import { OrganizationsPage } from "../features/organizations/components/OrganizationsPage";
import { ScansPage } from "../features/scans/components/ScansPage";
import { ScanDetailPage } from "../features/scans/components/ScanDetailPage";
import { TargetsPage } from "../features/targets/components/TargetsPage";
import { RequireAuth } from "./RequireAuth";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<AuthPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="/organizations" element={<OrganizationsPage />} />
        <Route path="/conversations" element={<ConversationsPage />} />
        <Route path="/audit-log" element={<AuditLogPage />} />
      </Route>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}
