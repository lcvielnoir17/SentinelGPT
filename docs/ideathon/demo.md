# Ideathon demo script

End-to-end demonstration of the four Google integrations (Firebase,
Firestore, Gemini, Secret Manager/Cloud Run). Works identically against a
Cloud Run deployment or a local stack — only the URLs differ.

## Preparation

* Firebase project with Google sign-in enabled ([setup.md](setup.md)).
* At least one completed scan with findings (run a scan from the Targets →
  Scans UI first; on Cloud Run the scanner is disabled, so point the demo
  at data created earlier or seed via the API).

## 1. Firebase Authentication (requirement 1)

1. Open the frontend. On the login screen choose **Sign in with Google**.
2. Complete the Google popup; the app exchanges the Firebase ID token at
   `POST /api/v1/auth/firebase`, which verifies it server-side and issues
   SentinelGPT's own session cookies.
3. The dashboard loads under your identity. (Classic email/password login
   still works — the Firebase identity linked to the same verified email
   maps to the same account.)

## 2. Gemini multi-turn analyst (requirement 2)

1. Open **Scans → a scan with findings**.
2. On any finding click **Ask SentinelGPT**.
3. Ask a grounded question, e.g.
   *"Explain this finding like I'm new to security — what exactly is the risk?"*
4. Ask a follow-up that requires memory of turn 1, e.g.
   *"Give me concrete nginx config to fix it"* — the analyst answers in
   context; nothing has to be restated.
5. Ask for a summary: *"Summarize this conversation as a report section."*
6. Navigate away and back: the full history is there (it lived in
   Firestore, requirement 3).

What to point out: the finding's raw scanner evidence travels inside a
framed `<untrusted_target_data>` block — attacker text in scan output is
treated as evidence, never as instructions.

## 3. Firestore user isolation (requirement 3)

1. In a second browser profile, sign in as a different Google account.
2. Open **Conversations**: the list is empty — no leakage of user A's
   conversations.
3. (Optional, API-level proof) from user B's session call
   `GET /api/v1/conversations/{user-A-conversation-id}` → **404**.
   Cross-owner ids are indistinguishable from unknown ids.

## 4. Secret Manager (requirement 4)

1. Show that no key is anywhere in the frontend bundle or any API
   response: `GET /healthz` exposes only boolean flags.
2. Rotate the secret:

   ```bash
   printf '%s' "$NEW_GEMINI_API_KEY" | \
     gcloud secrets versions add gemini-api-key --data-file=- --project "$PROJECT_ID"
   ```

3. Within ~5 minutes (the resolver's cache TTL) new conversations use the
   new key — no redeploy.

## 5. Cloud Run (requirement 5)

```bash
gcloud run services list --project "$PROJECT_ID"
gcloud run services describe sentinelgpt-api --region "$REGION" \
    --format 'value(status.url)'
```

Show both services running, the frontend proxying `/api` same-origin, and
`/healthz` green. The scanner worker deliberately runs elsewhere
(see [cloud-run.md](cloud-run.md)).

## Command-line alternative (no UI)

```bash
# after signing in through the UI, copy the session cookie from devtools
curl -s -X POST "$API/api/v1/conversations" \
  -H 'Content-Type: application/json' -b "$COOKIE" \
  -d '{"scanId":"<scan-uuid>","findingId":"<finding-uuid>"}'
curl -s -X POST "$API/api/v1/conversations/<id>/messages" \
  -H 'Content-Type: application/json' -b "$COOKIE" \
  -d '{"content":"What is the most severe finding here and why?"}'
```

Unauthenticated calls to the same endpoints return **401** — the analyst
surface is never callable anonymously.
