/**
 * Post-login deep-link return (release audit D5).
 *
 * RequireAuth stores the guarded URL as `state.from`; AuthPage navigates
 * back there after login instead of always landing on /dashboard.
 * Absolute or protocol-relative targets are never honored.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthPage } from "./AuthPage";
import { AuthProvider } from "../../../app/AuthContext";
import { login, me } from "../api/authApi";

vi.mock("../api/authApi", () => ({
  login: vi.fn(),
  logout: vi.fn(),
  me: vi.fn(),
  register: vi.fn(),
  firebaseLogin: vi.fn(),
}));

const mockedLogin = vi.mocked(login);
const mockedMe = vi.mocked(me);

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="loc">{location.pathname}</span>;
}

function renderAt(entry: unknown) {
  return render(
    <MemoryRouter initialEntries={[entry as never]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<AuthPage />} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

async function signIn() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), "a@example.com");
  await user.type(screen.getByLabelText(/Password/), "correct-horse-battery-pw");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

beforeEach(() => {
  vi.resetAllMocks();
  mockedMe.mockRejectedValue(new Error("no session"));
  mockedLogin.mockResolvedValue({
    user: { id: "u1", email: "a@example.com", mfaEnabled: false, organizations: [] },
    expiresIn: 900,
  });
});

describe("AuthPage post-login redirect", () => {
  it("returns to the guarded deep link after login", async () => {
    renderAt({ pathname: "/login", state: { from: "/scans/abc123" } });
    await signIn();
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/scans/abc123"));
    expect(mockedLogin).toHaveBeenCalledTimes(1);
  });

  it("falls back to /dashboard without a deep link", async () => {
    renderAt("/login");
    await signIn();
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/dashboard"));
  });

  it("never honors absolute or protocol-relative targets", async () => {
    renderAt({ pathname: "/login", state: { from: "https://evil.example/phish" } });
    await signIn();
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/dashboard"));
  });
});
