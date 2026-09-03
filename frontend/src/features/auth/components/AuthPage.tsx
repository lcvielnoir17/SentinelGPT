/**
 * Login / registration screen — Phase 0 deliverable (SRS Chapter 15, Section 2:
 * "a working login screen against a stubbed auth endpoint").
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import { useAuth } from "../../../app/AuthContext";

type Mode = "login" | "register";

export function AuthPage() {
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [googleBusy, setGoogleBusy] = useState(false);
  const { login, register, signInWithGoogle, firebaseEnabled } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password);
      }
      navigate("/dashboard", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Unable to reach the SentinelGPT API.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleGoogleSignIn() {
    setError(null);
    setGoogleBusy(true);
    try {
      await signInWithGoogle();
      navigate("/dashboard", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else if (err instanceof Error && err.name !== "FirebaseError") {
        setError(err.message);
      } else {
        setError("Google sign-in failed or was cancelled.");
      }
    } finally {
      setGoogleBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card" aria-label="Authentication">
        <h1>SentinelGPT</h1>
        <p className="auth-subtitle">AI-powered vulnerability analysis</p>

        <div className="mode-toggle" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "login"}
            className={mode === "login" ? "active" : ""}
            onClick={() => setMode("login")}
          >
            Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "register"}
            className={mode === "register" ? "active" : ""}
            onClick={() => setMode("register")}
          >
            Create account
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <label htmlFor="password">
            Password
            {mode === "register" && <span className="hint"> (minimum 12 characters)</span>}
          </label>
          <input
            id="password"
            type="password"
            minLength={mode === "register" ? 12 : 1}
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "register" ? "new-password" : "current-password"}
          />

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" disabled={busy}>
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>

        {firebaseEnabled && (
          <>
            <div className="auth-divider" aria-hidden="true">
              <span>or</span>
            </div>
            <button
              type="button"
              className="google-signin"
              onClick={handleGoogleSignIn}
              disabled={googleBusy || busy}
            >
              {googleBusy ? "Connecting…" : "Continue with Google"}
            </button>
            <p className="hint auth-hint">
              Firebase-authenticated sign-in (Google) exchanged for a SentinelGPT session.
            </p>
          </>
        )}
      </section>
    </main>
  );
}
