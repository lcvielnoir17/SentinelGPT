/**
 * Regression tests for the ScanDetailPage findings triage filter.
 *
 * The findings list supports client-side severity filtering + text search
 * so analysts can triage large scans. Contract:
 *
 * 1. all findings render by default with per-severity counts;
 * 2. choosing a severity shows only matching findings;
 * 3. typing a query matches title/description/location;
 * 4. clearing restores the full list (report downloads are unaffected —
 *    they always export every finding server-side).
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanDetailPage } from "./ScanDetailPage";
import {
  getAssessment,
  getFindingExplanation,
  getScan,
  listFindings,
  listScans,
} from "../api/scansApi";
import type { Finding, Scan } from "../api/scansApi";

vi.mock("../api/scansApi", () => ({
  cancelScan: vi.fn(),
  compareScans: vi.fn(),
  getAssessment: vi.fn(),
  getFindingExplanation: vi.fn(),
  getScan: vi.fn(),
  listFindings: vi.fn(),
  listScans: vi.fn(),
  rescanScan: vi.fn(),
}));

vi.mock("../../reports/reportsApi", () => ({
  downloadScanReport: vi.fn(),
}));

vi.mock("../../conversations/api/conversationsApi", () => ({
  listConversations: vi.fn().mockResolvedValue([]),
  createConversation: vi.fn(),
  getConversation: vi.fn(),
  sendMessage: vi.fn(),
}));

const SCAN_ID = "11111111-1111-4111-8111-111111111111";

function scan(): Scan {
  return {
    id: SCAN_ID,
    targetId: "22222222-2222-4222-8222-222222222222",
    scanProfile: "standard",
    status: "REPORT_READY",
    initiatedBy: "user-1",
    authorizationAttestationId: "33333333-3333-4333-8333-333333333333",
    queuedAt: null,
    startedAt: null,
    completedAt: null,
    createdAt: "2026-09-04T10:00:00Z",
  };
}

function finding(partial: Partial<Finding> & { id: string }): Finding {
  return {
    title: `Finding ${partial.id}`,
    description: `Description for ${partial.id}`,
    severity: "medium",
    evidence: "evidence",
    location: "https://example.com/",
    recommendation: "Fix it.",
    createdAt: "2026-09-04T10:00:00Z",
    ...partial,
  };
}

const FINDINGS: Finding[] = [
  finding({
    id: "f-crit",
    title: "Missing security headers",
    severity: "critical",
    location: "https://example.com/",
  }),
  finding({
    id: "f-high",
    title: "Verbose server banner",
    description: "The Server header leaks version details.",
    severity: "high",
    location: "https://example.com/app",
  }),
  finding({
    id: "f-low",
    title: "Cookie without prefix",
    severity: "low",
    location: "https://example.com/login",
  }),
];

function renderPage() {
  return render(
    <MemoryRouter initialEntries={[`/scans/${SCAN_ID}`]}>
      <Routes>
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getScan).mockResolvedValue(scan());
  vi.mocked(listFindings).mockResolvedValue(FINDINGS);
  vi.mocked(listScans).mockResolvedValue([]);
  vi.mocked(getAssessment).mockResolvedValue({
    available: false,
    provider: "none",
    model: "none",
    promptSchemaVersion: "v1",
    outputSchemaVersion: "v1",
    failureKind: "AI_NOT_CONFIGURED",
    unsupportedClaimCount: 0,
    payload: {},
    createdAt: "2026-09-04T10:00:00Z",
  });
  vi.mocked(getFindingExplanation).mockResolvedValue({
    available: false,
    validationStatus: "FALLBACK_USED",
  });
});

async function waitForFindings() {
  await waitFor(() => {
    expect(screen.getByText("Missing security headers")).toBeInTheDocument();
  });
  expect(screen.getByText("Verbose server banner")).toBeInTheDocument();
  expect(screen.getByText("Cookie without prefix")).toBeInTheDocument();
}

describe("ScanDetailPage findings filter", () => {
  it("renders every finding with severity counts by default", async () => {
    renderPage();
    await waitForFindings();
    const select = screen.getByLabelText("Severity");
    const options = within(select as HTMLSelectElement).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual([
      "All severities (3)",
      "critical (1)",
      "high (1)",
      "low (1)",
    ]);
  });

  it("filters to the chosen severity and restores on clear", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitForFindings();

    await user.selectOptions(screen.getByLabelText("Severity"), "high");
    expect(screen.queryByText("Missing security headers")).not.toBeInTheDocument();
    expect(screen.getByText("Verbose server banner")).toBeInTheDocument();
    expect(screen.queryByText("Cookie without prefix")).not.toBeInTheDocument();

    // Narrow to an empty result so the empty-state clear action appears.
    await user.type(screen.getByLabelText("Search"), "zzz-no-such-finding");
    expect(screen.queryByText("Verbose server banner")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitForFindings();
  });

  it("searches title, description, and location", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitForFindings();

    // Description match.
    await user.type(screen.getByLabelText("Search"), "leaks version");
    expect(screen.queryByText("Missing security headers")).not.toBeInTheDocument();
    expect(screen.getByText("Verbose server banner")).toBeInTheDocument();

    // Location match.
    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), "/login");
    expect(screen.queryByText("Verbose server banner")).not.toBeInTheDocument();
    expect(screen.getByText("Cookie without prefix")).toBeInTheDocument();
  });
});
