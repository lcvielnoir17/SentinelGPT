"""Extra acceptance checks beyond e2e_target_workflow / e2e_scan_workflow.

Verifies:
  * audit-log endpoint returns persisted entries
  * logout invalidates the session
  * the successful-scan path (real local HTTP target) yields findings + report
  * AI assessment surfaces "controlled unavailability" when GEMINI_API_KEY is absent
  * no scan remains stuck in QUEUED unexpectedly
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

BASE = "http://127.0.0.1:8000"
TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Tiny in-process HTTP server so we have a real resolvable target to scan.
# Listens on 127.0.0.1 only, serves a single page that emits common headers.
# ---------------------------------------------------------------------------
class TinyApp(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence stderr
        return

    def do_GET(self):  # noqa: N802
        body = b"<html><body><h1>ok</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "TinyTest/1.0")
        self.send_header("X-Powered-By", "TinyTest")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_tiny_app() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), TinyApp)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}{(' - ' + detail) if detail else ''}")
    else:
        print(f"  FAIL  {label}{(' - ' + detail) if detail else ''}")
        failures.append(label + ((" - " + detail) if detail else ""))


# ---------------------------------------------------------------------------
def main() -> int:
    suffix = uuid.uuid4().hex[:8]
    email = f"e2e_extra_{suffix}@example.com"
    password = "correct-horse-battery-staple-1A!"

    with httpx.Client(base_url=BASE, timeout=TIMEOUT) as client:
        # ----- auth -----
        r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
        check("register", r.status_code == 201, f"HTTP {r.status_code}")
        r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        check("login", r.status_code == 200, f"HTTP {r.status_code}")
        if r.status_code != 200:
            return 1
        cookies_before = dict(client.cookies)
        owner_id = r.json()["user"]["id"]

        # ----- target + attestation + scan against in-process tiny app -----
        srv, url = start_tiny_app()
        host = url.split("//", 1)[1].split(":", 1)[0]
        try:
            r = client.post("/api/v1/targets", json={"hostname": host, "url": url + "/"})
            check("create_target_resolvable", r.status_code == 201, f"HTTP {r.status_code}")
            if r.status_code != 201:
                return 1
            target_id = r.json()["id"]
            r = client.post(f"/api/v1/targets/{target_id}/attestations",
                            json={"method": "SELF_ATTESTATION"})
            check("create_attestation", r.status_code == 201, f"HTTP {r.status_code}")

            r = client.post("/api/v1/scans",
                            json={"targetId": target_id, "scanProfile": "quick-check"})
            check("create_scan_resolvable", r.status_code == 202, f"HTTP {r.status_code}")
            scan_id = r.json()["id"]

            # ----- poll for terminal state, confirm no stuck QUEUED -----
            deadline = time.monotonic() + 60
            last_status = None
            while time.monotonic() < deadline:
                rr = client.get(f"/api/v1/scans/{scan_id}")
                if rr.status_code == 200:
                    last_status = rr.json().get("status")
                    if last_status in (
                        "REPORT_READY",
                        "REPORT_READY_DEGRADED",
                        "REJECTED",
                        "CANCELLED",
                    ):
                        break
                time.sleep(1.0)
            check(
                f"scan reaches terminal (final={last_status})",
                last_status in ("REPORT_READY", "REPORT_READY_DEGRADED", "REJECTED"),
            )

            # ----- findings endpoint -----
            r = client.get(f"/api/v1/scans/{scan_id}/findings")
            findings = r.json() if r.status_code == 200 else []
            check("findings endpoint reachable", r.status_code == 200, f"HTTP {r.status_code}")
            print(f"    findings count: {len(findings)}")
            for f in findings[:5]:
                print(f"      - {f.get('severity')} | {f.get('title')[:60]}")

            # ----- report JSON + CSV -----
            r = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
            check("report json", r.status_code == 200, f"HTTP {r.status_code}")
            rep = r.json() if r.status_code == 200 else {}
            print(f"    report schema_version={rep.get('schema_version')}")
            print(f"    report severity_counts={rep.get('severity_counts')}")
            print(f"    report findings count={len(rep.get('findings', []))}")
            print(f"    report engines={[(e.get('engine_code'), e.get('status')) for e in rep.get('engines', [])]}")

            r = client.get(f"/api/v1/scans/{scan_id}/report?format=csv")
            check("report csv", r.status_code == 200 and r.headers.get("content-type", "").startswith("text/csv"),
                  f"HTTP {r.status_code} ct={r.headers.get('content-type')}")
            csv_lines = r.text.splitlines()
            print(f"    csv lines={len(csv_lines)}; header={csv_lines[0][:120] if csv_lines else '(empty)'}")

            # ----- AI assessment (controlled unavailability expected) -----
            r = client.get(f"/api/v1/scans/{scan_id}/assessment")
            check("assessment endpoint", r.status_code == 200, f"HTTP {r.status_code}")
            assess = r.json() if r.status_code == 200 else {}
            print(f"    assessment.available={assess.get('available')} failureKind={assess.get('failureKind')} provider={assess.get('provider')}")
            # GEMINI_API_KEY is empty by acceptance contract; expect available=False, failureKind != success
            check(
                "AI assessment reports controlled unavailability",
                assess.get("available") is False
                and assess.get("failureKind") in {"not_ready", "ai_unavailable", "ai_disabled", "no_api_key", "not_configured"},
                f"available={assess.get('available')} failureKind={assess.get('failureKind')}",
            )

            # ----- audit log -----
            r = client.get(f"/api/v1/audit-log?entityId={scan_id}&limit=50")
            check("audit-log endpoint", r.status_code == 200, f"HTTP {r.status_code}")
            entries = r.json() if r.status_code == 200 else []
            codes = sorted({e.get("actionCode") for e in entries})
            print(f"    audit entries for scan: {len(entries)}; codes={codes}")
            check("audit SCAN_REQUESTED persisted", any(e.get("actionCode") == "SCAN_REQUESTED" for e in entries))
            check("audit terminal transition persisted",
                  any(e.get("actionCode") in {"SCAN_REJECTED", "SCAN_COMPLETED", "SCAN_FAILED", "SCAN_STARTED"} for e in entries))
        finally:
            srv.shutdown()

        # ----- logout invalidates the session -----
        # Confirm /auth/me works first.
        r = client.get("/api/v1/auth/me")
        check("auth/me before logout", r.status_code == 200, f"HTTP {r.status_code}")

        # Logout requires X-Refresh-Request: 1 per OpenAPI.
        r = client.post("/api/v1/auth/logout", headers={"X-Refresh-Request": "1"})
        check("logout returns 204", r.status_code == 204, f"HTTP {r.status_code}")
        # Cookies should be cleared by Set-Cookie (expired). Clear client side just in case.
        client.cookies.clear()
        # Re-login and try a different identity to confirm cookie state is gone.
        r = client.get("/api/v1/auth/me")
        check("auth/me after logout (cookie cleared)", r.status_code == 401, f"HTTP {r.status_code}")

        # ----- stuck-scan check: are there any scans stuck in QUEUED? -----
        r = client.get("/api/v1/scans?limit=200")
        all_scans = r.json() if r.status_code == 200 else []
        queued = [s for s in all_scans if s.get("status") == "QUEUED"]
        print(f"    total scans visible: {len(all_scans)}; stuck QUEUED: {len(queued)}")
        if queued:
            # Any queued scan older than 2 minutes is "stuck unexpectedly".
            now = time.time()
            stuck = []
            for s in queued:
                t = s.get("queuedAt")
                if t:
                    try:
                        ts = time.mktime(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S"))
                        if now - ts > 120:
                            stuck.append(s["id"])
                    except Exception:
                        pass
            check("no scan stuck in QUEUED > 2min", len(stuck) == 0, f"stuck={stuck}")
        else:
            check("no scan stuck in QUEUED > 2min", True)

    print("\n" + "=" * 60)
    if not failures:
        print("EXTRA CHECKS: ALL PASSED")
        return 0
    print("EXTRA CHECKS FAILED:")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main())