/**
 * Authentication state provider.
 *
 * PHASE 0 BEHAVIOR (intentionally temporary, per SRS Chapter 15 Section 2):
 * the authenticated identity is held in memory only. The backend's Phase 0
 * login endpoint performs REAL credential verification but issues no token
 * material — consistent with the v3 invariant that JavaScript never receives
 * or stores JWTs. Phase 1 replaces this context with server-verified
 * HttpOnly-cookie sessions restored via GET /auth/me on page load.
 */

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { UserAccount } from "../features/auth/api/authApi";
import { login as apiLogin, register as apiRegister } from "../features/auth/api/authApi";

interface AuthContextValue {
  user: UserAccount | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserAccount | null>(null);

  const login = useCallback(async (email: string, password: string) => {
    const response = await apiLogin(email, password);
    setUser(response.user);
  }, []);

  const register = useCallback(
    async (email: string, password: string) => {
      await apiRegister(email, password);
      // Auto-login after successful registration so the Phase 0 flow
      // ("register → land on dashboard") works in one pass.
      const response = await apiLogin(email, password);
      setUser(response.user);
    },
    [],
  );

  const logout = useCallback(() => {
    // PHASE 0: nothing to revoke yet; Phase 1 adds POST /auth/logout.
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ user, login, register, logout }),
    [user, login, register, logout],
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
