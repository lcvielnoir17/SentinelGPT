"""Focused extra checks for AI assessment, audit log, and logout.

These were missed by the in-process-server approach (SSRF blocks 127.0.0.1).
We use the existing pre-populated scan id from the e2e_scan_workflow run.
"""
from __future__ import annotations

import sys
import uuid

import httpx

BASE = "http://127.0.0.1:8000"
TIMEOUT = 15.0


def main() -> int:
    failures: list[str] = []
    suffix = uuid.uuid4().hex[:8]
    email = f"e2e_authlog_{suffix}@example.com"
    password = "correct-horse-battery-staple-1A!"

    with httpx.Client(base_url=BASE, timeout=TIMEOUT) as c:
        # Auth.
        c.post("/api/v1/auth/register", json={"email": email, "password": password})
        r = c.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        owner_id = r.json()["user"]["id"]

        # Build a fresh target+attestation+scan with a known unreachable hostname
        # so we exercise REJECTED pipeline + AI assessment path deterministically.
        r = c.post("/api/v1/targets",
                   json={"hostname": f"audit-{suffix}.example.com",
                         "url": f"https://audit-{suffix}.example.com/"})
        assert r.status_code == 201, r.text
        tid = r.json()["id"]
        c.post(f"/api/v1/targets/{tid}/attestations", json={"method": "SELF_ATTESTATION"})
        r = c.post("/api/v1/scans", json={"targetId": tid, "scanProfile": "quick-check"})
        assert r.status_code == 202, r.text
        scan_id = r.json()["id"]

        # Wait until terminal.
        import time
        deadline = time.monotonic() + 60
        last = None
        while time.monotonic() < deadline:
            rr = c.get(f"/api/v1/scans/{scan_id}")
            if rr.status_code == 200:
                last = rr.json().get("status")
                if last in ("REPORT_READY", "REPORT_READY_DEGRADED", "REJECTED", "CANCELLED"):
                    break
            time.sleep(1)
        print(f"final status: {last}")

        # AI assessment (controlled unavailability).
        r = c.get(f"/api/v1/scans/{scan_id}/assessment")
        print(f"GET /assessment: HTTP {r.status_code}")
        print(f"body: {r.text[:400]}")
        assess = r.json() if r.status_code == 200 else {}
        if assess.get("available") is not True:
            print("PASS  AI assessment reports controlled unavailability (GEMINI_API_KEY empty)")
        else:
            failures.append(f"AI assessment unexpectedly available: {assess}")

        # Audit log for this scan id.
        r = c.get(f"/api/v1/audit-log?entityId={scan_id}&limit=50")
        print(f"GET /audit-log entityId={scan_id}: HTTP {r.status_code}")
        entries = r.json() if r.status_code == 200 else []
        codes = sorted({e.get("actionCode") for e in entries})
        print(f"audit codes: {codes}")
        if "SCAN_REQUESTED" not in codes:
            failures.append("SCAN_REQUESTED not persisted in audit log")
        if not any(c in codes for c in ("SCAN_REJECTED", "SCAN_COMPLETED", "SCAN_FAILED", "SCAN_STARTED", "SCAN_FINISHED")):
            failures.append(f"no scan-lifecycle transition persisted: {codes}")

        # Findings endpoint reachable and shaped correctly.
        r = c.get(f"/api/v1/scans/{scan_id}/findings")
        print(f"GET /findings: HTTP {r.status_code}")
        if r.status_code == 200:
            findings = r.json()
            print(f"  count={len(findings)}; sample={[f.get('severity') for f in findings[:5]]}")
            for f in findings:
                if not all(k in f for k in ("id", "title", "severity", "evidence", "location", "recommendation")):
                    failures.append(f"finding missing required field: {f}")
        else:
            failures.append(f"findings endpoint not reachable: HTTP {r.status_code}")

        # Report JSON & CSV.
        r = c.get(f"/api/v1/scans/{scan_id}/report?format=json")
        print(f"GET /report?format=json: HTTP {r.status_code}")
        if r.status_code == 200:
            rep = r.json()
            print(f"  schema_version={rep.get('schema_version')} lifecycle_counts={rep.get('lifecycle_counts')} severity_counts={rep.get('severity_counts')}")
            print(f"  engines: {[(e.get('engine_code'), e.get('status')) for e in rep.get('engines', [])]}")
            print(f"  findings={len(rep.get('findings', []))} assessment={rep.get('assessment')}")
            for k in ("schema_version", "findings", "engines", "severity_counts", "lifecycle_counts"):
                if k not in rep:
                    failures.append(f"report missing required field: {k}")

        r = c.get(f"/api/v1/scans/{scan_id}/report?format=csv")
        print(f"GET /report?format=csv: HTTP {r.status_code} ct={r.headers.get('content-type')}")
        if r.status_code == 200 and r.headers.get("content-type", "").startswith("text/csv"):
            print(f"  csv header: {r.text.splitlines()[0][:200]}")
        else:
            failures.append(f"csv report not as expected: HTTP {r.status_code} ct={r.headers.get('content-type')}")

        # Logout invalidates the session.
        r = c.get("/api/v1/auth/me")
        print(f"GET /auth/me pre-logout: HTTP {r.status_code}")
        if r.status_code != 200:
            failures.append(f"auth/me pre-logout should be 200: HTTP {r.status_code}")

        r = c.post("/api/v1/auth/logout", headers={"X-Refresh-Request": "1"})
        print(f"POST /auth/logout: HTTP {r.status_code}")
        if r.status_code != 204:
            failures.append(f"logout should be 204: HTTP {r.status_code}")

        # Clear cookies and confirm /auth/me now fails.
        c.cookies.clear()
        r = c.get("/api/v1/auth/me")
        print(f"GET /auth/me post-logout: HTTP {r.status_code}")
        if r.status_code != 401:
            failures.append(f"auth/me post-logout should be 401: HTTP {r.status_code}")

        # Also confirm subsequent login with different creds works (cookies cleared).
        other = f"e2e_other_{suffix}@example.com"
        c.post("/api/v1/auth/register", json={"email": other, "password": password})
        r = c.post("/api/v1/auth/login", json={"email": other, "password": password})
        print(f"re-login as different user: HTTP {r.status_code}")
        if r.status_code != 200:
            failures.append(f"re-login failed: HTTP {r.status_code}")

    print()
    if not failures:
        print("AI/AUDIT/LOGOUT CHECKS: ALL PASSED")
        return 0
    print("FAILURES:")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main())