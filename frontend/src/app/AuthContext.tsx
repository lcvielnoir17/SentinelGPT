/**
 * Authentication state provider.
 *
 * Phase 1 behavior (SRS Chapter 5, Section 2):
 *   - Login / register POST sets two HttpOnly cookies (access JWT and
 *     refresh credential). Token material is never visible to JavaScript.
 *   - The in-memory `user` is the only authoritative client-side identity
 *     signal; there is no localStorage / sessionStorage round-trip.
 *   - On startup the SPA issues a single bootstrap `GET /auth/me` to
 *     restore the in-memory user from the still-attached HttpOnly access
 *     cookie. ``bootstrap === "pending"`` while the probe is in flight
 *     so ``RequireAuth`` can render a placeholder instead of redirecting
 *     to /login (which would otherwise flash a 401 → /login round-trip
 *     on every page load).
 *   - Sign-out calls `POST /auth/logout` to revoke the refresh credential
 *     server-side and clear both cookies (the `X-Refresh-Request` header
 *     is a CSRF mitigation per SRS Ch2 §9).
 *   - Any 401 response from the API after bootstrap completes triggers an
 *     automatic sign-out and a redirect to `/login` so an expired access
 *     JWT never strands the user. The 401 handler is gated on bootstrap
 *     completion: during the bootstrap probe itself, a 401 is treated as
 *     "no active session" (not a navigation event).
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import type { UserAccount } from "../features/auth/api/authApi";
import {
  login as apiLogin,
  logout as apiLogout,
  me as apiMe,
  register as apiRegister,
  firebaseLogin as apiFirebaseLogin,
} from "../features/auth/api/authApi";
import { ApiError, setUnauthorizedHandler } from "../services/apiClient";
import { firebaseEnabled as isFirebaseEnabled, getFirebaseAuth } from "../services/firebase";
import { invalidateTargetsCache } from "../features/targets/api/targetsData";

type BootstrapState = "pending" | "ready";

interface AuthContextValue {
  user: UserAccount | null;
  bootstrap: BootstrapState;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Firebase (Google) sign-in: ID token verified server-side (ADR-0010). */
  signInWithGoogle: () => Promise<void>;
  firebaseEnabled: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserAccount | null>(null);
  const [bootstrap, setBootstrap] = useState<BootstrapState>("pending");
  const navigate = useNavigate();

  // One-shot session restore on app mount. The probe is the only
  // request that is allowed to happen while bootstrap is "pending":
  // every other auth-aware UI waits on the bootstrap state so a valid
  // session never briefly renders the login screen.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const account = await apiMe();
        if (!cancelled) {
          setUser(account);
        }
      } catch (err) {
        // 401 (or any other failure) is treated as "no active session".
        // We deliberately do NOT navigate from here — the
        // setUnauthorizedHandler below gates navigation on bootstrap
        // completion so the bootstrap response itself can't cause a
        // /login flash.
        if (!cancelled) {
          setUser(null);
        }
        if (!(err instanceof ApiError)) {
          // Network / unexpected error: log nothing in the console; the
          // bootstrap state is allowed to finish so the UI can render
          // the login screen via RequireAuth's natural redirect.
        }
      } finally {
        if (!cancelled) {
          setBootstrap("ready");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const response = await apiLogin(email, password);
    // Drop any cached rows from a previous identity in this tab.
    invalidateTargetsCache();
    setUser(response.user);
  }, []);

  const register = useCallback(
    async (email: string, password: string) => {
      await apiRegister(email, password);
      // Auto-login after successful registration so the flow
      // ("register → land on dashboard") works in one pass.
      const response = await apiLogin(email, password);
      invalidateTargetsCache();
      setUser(response.user);
    },
    [],
  );

  const logout = useCallback(async () => {
    // Best-effort server-side revocation; even if it fails (e.g. the
    // access cookie has already expired) the in-memory state is cleared
    // and the user is bounced to /login.
    try {
      await apiLogout();
    } catch {
      // Swallow — local sign-out proceeds regardless.
    }
    // The module-level targets cache must not survive the identity:
    // otherwise the next login in this tab briefly renders the previous
    // user's rows. Best-effort Firebase sign-out as well so the Google
    // account chooser does not silently re-offer the old session.
    invalidateTargetsCache();
    try {
      const { getAuth, signOut } = await import("firebase/auth");
      const { getApps } = await import("firebase/app");
      if (getApps().length > 0) {
        await signOut(getAuth());
      }
    } catch {
      // Firebase absent or already signed out — nothing to do.
    }
    setUser(null);
  }, []);

  // Firebase bridge (ADR-0010): the popup produces a Google ID token; the
  // backend verifies it against Google's public keys and issues the same
  // HttpOnly cookie session as email/password login. The Firebase session
  // itself is not consulted again — the cookie session is canonical. The
  // SDK loads on demand so non-Google users never download it.
  const signInWithGoogle = useCallback(async () => {
    const auth = await getFirebaseAuth();
    if (auth === null) {
      throw new Error("Firebase sign-in is not configured on this deployment.");
    }
    let popup: typeof import("firebase/auth");
    try {
      popup = await import("firebase/auth");
    } catch {
      throw new Error("Firebase sign-in failed to load. Check your connection and retry.");
    }
    const provider = new popup.GoogleAuthProvider();
    const credential = await popup.signInWithPopup(auth, provider);
    const idToken = await credential.user.getIdToken();
    const response = await apiFirebaseLogin(idToken);
    invalidateTargetsCache();
    setUser(response.user);
  }, []);

  // Register the global 401 → "go to /login" handler so an expired access
  // JWT never strands the user on a page that can't reach the API. The
  // handler is a no-op while bootstrap is in flight: a 401 during the
  // bootstrap probe means "no active session", not "active session that
  // just expired", so we let the in-flight probe resolve naturally and
  // RequireAuth handles the resulting user === null state.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      if (bootstrap !== "ready") return;
      setUser(null);
      navigate("/login", { replace: true });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate, bootstrap]);

  const value = useMemo<AuthContextValue>(
    () => ({ user, bootstrap, login, register, logout, signInWithGoogle, firebaseEnabled: isFirebaseEnabled }),
    [user, bootstrap, login, register, logout, signInWithGoogle],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}