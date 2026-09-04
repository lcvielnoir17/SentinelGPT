/**
 * Logout identity hygiene: cached rows must not survive the identity.
 *
 * Regression test for the cross-user targets-cache leak: the targets
 * loader keeps a module-level cache, so logout (and any re-login) must
 * invalidate it — otherwise the next login in the same tab briefly
 * renders the previous user's rows. Logout must also best-effort sign
 * out the Firebase SDK session.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./AuthContext";
import { listAttestations, listTargets } from "../features/targets/api/targetsApi";
import { loadTargets, invalidateTargetsCache } from "../features/targets/api/targetsData";
import { login, logout, me } from "../features/auth/api/authApi";

vi.mock("../features/auth/api/authApi", () => ({
  login: vi.fn(),
  logout: vi.fn(),
  me: vi.fn(),
  register: vi.fn(),
  firebaseLogin: vi.fn(),
}));

vi.mock("../features/targets/api/targetsApi", () => ({
  listTargets: vi.fn(),
  listAttestations: vi.fn(),
  createTarget: vi.fn(),
  getTarget: vi.fn(),
  setTargetArchived: vi.fn(),
  createSelfAttestation: vi.fn(),
}));

vi.mock("firebase/app", () => ({
  getApps: vi.fn(() => [{ name: "[DEFAULT]" }]),
  initializeApp: vi.fn(),
}));

vi.mock("firebase/auth", () => ({
  getAuth: vi.fn(() => ({})),
  signOut: vi.fn(() => Promise.resolve()),
}));

const mockedMe = vi.mocked(me);
const mockedLogout = vi.mocked(logout);
const mockedLogin = vi.mocked(login);
const mockedListTargets = vi.mocked(listTargets);
const mockedListAttestations = vi.mocked(listAttestations);

function account(id: string) {
  return { id, email: `${id}@example.com`, mfaEnabled: false, organizations: [] };
}

function Probe() {
  const { user, bootstrap, login: doLogin, logout: doLogout } = useAuth();
  return (
    <div>
      <span data-testid="user">{user ? user.id : "none"}</span>
      <span data-testid="bootstrap">{bootstrap}</span>
      <button type="button" onClick={() => void doLogin("a@example.com", "pw")}>
        login
      </button>
      <button type="button" onClick={() => void doLogout()}>
        logout
      </button>
    </div>
  );
}

function renderProbe() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Probe />
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
  invalidateTargetsCache();
  mockedMe.mockResolvedValue(account("user-a"));
  mockedLogout.mockResolvedValue(undefined);
  mockedLogin.mockResolvedValue({ user: account("user-a"), expiresIn: 900 });
  mockedListTargets.mockResolvedValue({ items: [], pageInfo: { nextCursor: null, hasNextPage: false } });
  mockedListAttestations.mockResolvedValue([]);
});

describe("AuthContext identity hygiene", () => {
  it("logout clears the cached targets so the next identity refetches", async () => {
    const user = userEvent.setup();
    renderProbe();
    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("user-a"));

    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "logout" }));
    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("none"));

    // Cache was invalidated: the next load hits the network again instead
    // of serving the previous identity's rows.
    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(2);
  });

  it("logout signs out the Firebase SDK session best-effort", async () => {
    const { signOut } = await import("firebase/auth");
    const user = userEvent.setup();
    renderProbe();
    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("user-a"));

    await user.click(screen.getByRole("button", { name: "logout" }));
    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("none"));
    expect(vi.mocked(signOut)).toHaveBeenCalledTimes(1);
  });

  it("login invalidates rows cached under a previous identity", async () => {
    const user = userEvent.setup();
    renderProbe();
    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("user-a"));

    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "login" }));
    await waitFor(() => expect(mockedLogin).toHaveBeenCalled());

    await loadTargets();
    expect(mockedListTargets).toHaveBeenCalledTimes(2);
  });
});
