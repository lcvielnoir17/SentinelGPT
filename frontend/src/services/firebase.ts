/**
 * Firebase Web SDK integration (Ideathon requirement 1, ADR-0010).
 *
 * Only PUBLIC Firebase web configuration lives here (apiKey included — the
 * web API key identifies the project, it does not authorize anything;
 * access control is enforced by the backend when it verifies the ID
 * token). Configuration comes from Vite env vars (VITE_FIREBASE_*), so a
 * deployment can point the SPA at its Firebase project without a rebuild
 * of the backend.
 *
 * When the variables are absent (plain local development) every helper
 * returns null and the UI hides the Firebase sign-in affordances — the
 * existing email/password session flow remains fully functional.
 *
 * The Firebase SDK itself is loaded lazily (dynamic `import()`): the ~300KB
 * auth bundle is fetched only when the user actually signs in with Google,
 * never as part of the initial page load.
 */

import type { Auth } from "firebase/auth";
import type { FirebaseApp } from "firebase/app";

const FIREBASE_API_KEY = import.meta.env.VITE_FIREBASE_API_KEY as string | undefined;
const FIREBASE_PROJECT_ID = import.meta.env.VITE_FIREBASE_PROJECT_ID as string | undefined;
const FIREBASE_APP_ID = import.meta.env.VITE_FIREBASE_APP_ID as string | undefined;

export const firebaseEnabled = Boolean(FIREBASE_API_KEY && FIREBASE_PROJECT_ID);

let cachedAuth: Auth | null = null;

export async function getFirebaseAuth(): Promise<Auth | null> {
  if (!firebaseEnabled) {
    return null;
  }
  if (cachedAuth !== null) {
    return cachedAuth;
  }
  const { initializeApp, getApps } = await import("firebase/app");
  const { getAuth } = await import("firebase/auth");
  const app: FirebaseApp =
    getApps()[0] ??
    initializeApp({
      apiKey: FIREBASE_API_KEY,
      projectId: FIREBASE_PROJECT_ID,
      appId: FIREBASE_APP_ID,
    });
  cachedAuth = getAuth(app);
  return cachedAuth;
}
