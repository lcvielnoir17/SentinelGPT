# Ideathon integration setup (Firebase, Firestore, Secret Manager)

This guide wires the Google-side resources for the Ideathon requirements.
Everything here is **additive**: with none of it configured, SentinelGPT
keeps working locally (email/password sessions, in-memory conversations,
env-provided Gemini key).

Architecture rationale lives in the ADRs:

* [ADR-0010](../adr/0010-firebase-identity-bridge.md) — Firebase auth bridge
* [ADR-0011](../adr/0011-firestore-conversation-persistence.md) — Firestore conversations
* [ADR-0012](../adr/0012-gemini-multi-turn-analyst.md) — Gemini multi-turn analyst
* [ADR-0013](../adr/0013-secret-manager-key-resolution.md) — Secret Manager key resolution

## 1. Firebase project + Authentication

1. Create (or choose) a Firebase project — it may be the same Google Cloud
   project you deploy to.
2. **Authentication → Sign-in method → enable Google.** (The frontend uses
   the Google popup flow; other federated providers work the same way.)
3. **Authentication → Settings → Authorized domains:** add your frontend
   origin(s) (e.g. the Cloud Run URL of the frontend service).
4. **Project settings → General → Your apps → Web app:** note
   `apiKey`, `projectId`, `appId`. These are the **public** web config —
   they go to the frontend only (`frontend/.env`):

   ```dotenv
   VITE_FIREBASE_API_KEY=...
   VITE_FIREBASE_PROJECT_ID=...
   VITE_FIREBASE_APP_ID=...
   ```

5. The backend needs only the **project ID** (`.env`):

   ```dotenv
   FIREBASE_PROJECT_ID=your-project
   ```

No Firebase Admin SDK credential exists anywhere in this project: ID tokens
are verified against Google's public JWKs (RS256, `aud`, `iss`, `exp`,
non-empty `sub`) with the project ID as the only configuration — see
`backend/src/domain/users/firebase_token_service.py`.

## 2. Firestore (user-isolated conversations)

1. **Firestore Database → Create database → Native mode**, any region.
   The default database id `(default)` is expected
   (`FIRESTORE_DATABASE_ID`); a named database also works.
2. Upload the deny-all rules (defense in depth — all access is backend
   Admin SDK / ADC, the SPA never touches Firestore):

   ```bash
   firebase deploy --only firestore:rules   # uses infra/firebase/firestore.rules
   ```

   Without the Firebase CLI, paste `infra/firebase/firestore.rules` into
   the Firebase console (Firestore → Rules) and publish.

3. Enable persistence in the backend (`.env`):

   ```dotenv
   FIRESTORE_CONVERSATIONS_ENABLED=true
   ```

The document model is `users/{firebase_uid}/conversations/{id}` with a
`messages` subcollection; every store call is scoped by the UID from the
**verified session**, never client input.

## 3. Secret Manager (Gemini API key)

1. Create a Gemini API key in Google AI Studio, then store it:

   ```bash
   printf '%s' "$GEMINI_API_KEY" | gcloud secrets create gemini-api-key \
       --data-file=- --project "$PROJECT_ID"
   ```

2. Point the backend at it (`.env`):

   ```dotenv
   GEMINI_API_KEY_SECRET=projects/$PROJECT_ID/secrets/gemini-api-key/versions/latest
   SECRET_MANAGER_ENABLED=true
   ```

3. Grant the runtime service account access:

   ```bash
   gcloud secrets add-iam-policy-binding gemini-api-key \
       --member "serviceAccount:RUNTIME_SA@$PROJECT_ID.iam.gserviceaccount.com" \
       --role roles/secretmanager.secretAccessor --project "$PROJECT_ID"
   ```

Locally, `gcloud auth application-default login` provides ADC; omitting
both variables falls back to plain `GEMINI_API_KEY` (development only).

## 4. Local development without any Google project

* Frontend without `VITE_FIREBASE_*` → Firebase sign-in is hidden;
  email/password login works.
* Backend without `FIREBASE_PROJECT_ID` → `POST /auth/firebase` answers
  503 `FEATURE_DISABLED`; conversations use the in-memory store with
  identical semantics (no durability).
* No Secret Manager config → `GEMINI_API_KEY` from the environment.

## Verification checklist

| Check | Expected |
|---|---|
| `GET /healthz` | `200`, reports firebase/firestore/gemini configured flags |
| Sign in with Google (frontend) | Session cookie set; dashboard loads |
| Create a conversation, send a message | 201; assistant reply; history persists after reload (Firestore) |
| Second user lists conversations | Only their own; other users' ids → 404 |
| `gcloud secrets versions access` NOT needed by app | Key resolved server-side via ADC |
