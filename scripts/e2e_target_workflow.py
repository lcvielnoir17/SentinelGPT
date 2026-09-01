"""E2E workflow verification script for the Target + Attestation API.

Runs against the local server at http://127.0.0.1:8000 and verifies the
complete lifecycle:
  1. login (cookies preserved)
  2. POST /targets (create)
  3. GET /targets (list)
  4. GET /targets/{id} (detail)
  5. PATCH /targets/{id} (immutability check + archive toggle)
  6. GET /targets/{id}/attestations (initial)
  7. POST /targets/{id}/attestations (create)
  8. GET /targets/{id}/attestations (post-create)
  9. auth boundary checks (unauth, other-user, owner)
"""

import json
import sys
import uuid

import httpx

BASE = "http://127.0.0.1:8000"
TIMEOUT = 15.0


def section(label: str) -> None:
    print("\n" + "=" * 72)
    print(label)
    print("=" * 72)


def show(label: str, response: httpx.Response) -> None:
    print(f"  {label}: HTTP {response.status_code}")
    try:
        body = response.json()
        print(f"    body: {json.dumps(body, default=str)[:400]}")
    except Exception:
        print(f"    body: {response.text[:200]}")


def main() -> int:
    # Use a fresh email so the script is re-runnable.
    suffix = uuid.uuid4().hex[:8]
    email = f"e2e_target_user_{suffix}@example.com"
    password = "correct-horse-battery-staple-1A!"
    print(f"using email: {email}")

    failures: list[str] = []
    target_id: str | None = None
    attestation_id: str | None = None

    with httpx.Client(base_url=BASE, timeout=TIMEOUT) as client:
        section("STEP 1 — register + login")
        r = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password},
        )
        show("register", r)
        if r.status_code not in (201, 409):
            failures.append(f"register unexpected status: {r.status_code}")

        r = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        show("login", r)
        if r.status_code != 200:
            failures.append(f"login failed: {r.status_code} {r.text}")
            return _summary(failures)
        # Print the cookies for visibility.
        for name, value in client.cookies.items():
            print(f"    cookie: {name}={value[:24]}...")

        section("STEP 2 — POST /targets (create legitimate test target)")
        create_payload = {
            "hostname": "e2e-test.example.com",
            "url": "https://e2e-test.example.com/health",
        }
        r = client.post("/api/v1/targets", json=create_payload)
        show("create_target", r)
        if r.status_code == 201:
            target_id = r.json()["id"]
            print(f"    captured target_id={target_id}")
        else:
            failures.append(f"create_target failed: {r.status_code} {r.text}")
            return _summary(failures)

        section("STEP 3 — verify target fields from create response")
        body = r.json()
        expected_keys = {
            "id",
            "hostname",
            "url",
            "ownerUserId",
            "status",
            "isArchived",
            "createdAt",
        }
        missing = expected_keys - set(body)
        if missing:
            failures.append(f"missing fields: {missing}")
        if body.get("hostname") != create_payload["hostname"]:
            failures.append(f"hostname mismatch: {body.get('hostname')}")
        if body.get("isArchived") is not False:
            failures.append(f"isArchived should be false, got {body.get('isArchived')}")
        if body.get("status") != "PENDING_ATTESTATION":
            failures.append(f"status should be PENDING_ATTESTATION, got {body.get('status')}")
        for k, v in body.items():
            print(f"    {k} = {v!r}")

        section("STEP 4 — GET /targets (list, must include new target)")
        r = client.get("/api/v1/targets")
        show("list_targets", r)
        if r.status_code != 200:
            failures.append(f"list_targets failed: {r.status_code}")
        else:
            items = r.json().get("items", [])
            if not any(item["id"] == target_id for item in items):
                failures.append("newly created target not in list response")
            else:
                print(f"    target {target_id} present in list (total={len(items)})")

        section("STEP 5 — GET /targets/{id} (detail)")
        r = client.get(f"/api/v1/targets/{target_id}")
        show("get_target", r)
        if r.status_code != 200:
            failures.append(f"get_target failed: {r.status_code}")
        elif r.json()["id"] != target_id:
            failures.append("detail returned wrong target id")

        section("STEP 6 — PATCH /targets/{id} (immutability + archive toggle)")
        # 6a: try to change hostname/URL — should be rejected (extra=forbid).
        r = client.patch(
            f"/api/v1/targets/{target_id}",
            json={"hostname": "evil.example.com", "url": "https://evil.example.com/"},
        )
        show("patch_hostname_forbidden", r)
        if r.status_code not in (400, 422):
            failures.append(f"hostname/URL mutation was not rejected: status={r.status_code}")

        # 6b: archive toggle works.
        r = client.patch(
            f"/api/v1/targets/{target_id}",
            json={"isArchived": True},
        )
        show("patch_archive_true", r)
        if r.status_code != 200:
            failures.append(f"archive toggle failed: {r.status_code}")
        elif r.json().get("isArchived") is not True:
            failures.append("isArchived did not flip to true")

        # 6c: archive toggle off again so subsequent steps work.
        r = client.patch(
            f"/api/v1/targets/{target_id}",
            json={"isArchived": False},
        )
        show("patch_archive_false", r)
        if r.status_code != 200:
            failures.append(f"archive re-open failed: {r.status_code}")

        section("STEP 7 — GET /targets/{id}/attestations (initial = empty)")
        r = client.get(f"/api/v1/targets/{target_id}/attestations")
        show("list_attestations_initial", r)
        if r.status_code != 200:
            failures.append(f"list attestations failed: {r.status_code}")
        elif r.json() != []:
            failures.append(f"initial attestation list not empty: {r.json()}")
        else:
            print("    initial list is empty as expected")

        section("STEP 8 — POST /targets/{id}/attestations (self-attest)")
        r = client.post(
            f"/api/v1/targets/{target_id}/attestations",
            json={"method": "SELF_ATTESTATION"},
        )
        show("create_attestation", r)
        if r.status_code == 201:
            attestation_id = r.json()["id"]
            print(f"    captured attestation_id={attestation_id}")
            if r.json().get("status") != "CONFIRMED":
                failures.append(
                    f"self-attestation should auto-confirm, got {r.json().get('status')}"
                )
        else:
            failures.append(f"create_attestation failed: {r.status_code} {r.text}")

        section("STEP 9 — GET attestations again (active must exist)")
        r = client.get(f"/api/v1/targets/{target_id}/attestations")
        show("list_attestations_post", r)
        if r.status_code != 200:
            failures.append(f"list attestations failed: {r.status_code}")
        else:
            items = r.json()
            print(f"    count={len(items)}")
            for a in items:
                print(f"    - {a['id']} status={a['status']} method={a['method']}")
            active = [a for a in items if a["status"] == "CONFIRMED"]
            if not active:
                failures.append("no CONFIRMED attestation in history after creation")

        section("STEP 10 — authorization boundaries")
        # 10a: unauthenticated request
        anon = httpx.Client(base_url=BASE, timeout=TIMEOUT)
        try:
            r = anon.get(f"/api/v1/targets/{target_id}")
            show("unauth_get_target", r)
            if r.status_code != 401:
                failures.append(f"unauth should be 401, got {r.status_code}")
        finally:
            anon.close()

        # 10b: a second authenticated user, with no membership/ownership.
        intruder_email = f"e2e_intruder_{suffix}@example.com"
        intruder_password = "another-strong-passw0rd!"
        with httpx.Client(base_url=BASE, timeout=TIMEOUT) as intruder:
            r = intruder.post(
                "/api/v1/auth/register",
                json={"email": intruder_email, "password": intruder_password},
            )
            if r.status_code not in (201, 409):
                print(f"  intruder register unexpected: {r.status_code}")
            r = intruder.post(
                "/api/v1/auth/login",
                json={"email": intruder_email, "password": intruder_password},
            )
            show("intruder_login", r)
            if r.status_code != 200:
                failures.append(f"intruder login failed: {r.status_code} {r.text}")
            else:
                # 10b-i: try to GET the other user's target -> 404 (not 403, per SRS)
                r = intruder.get(f"/api/v1/targets/{target_id}")
                show("intruder_get_target", r)
                if r.status_code != 404:
                    failures.append(f"cross-tenant GET should be 404, got {r.status_code}")
                # 10b-ii: try to PATCH someone else's target -> 404
                r = intruder.patch(
                    f"/api/v1/targets/{target_id}",
                    json={"isArchived": True},
                )
                show("intruder_patch_target", r)
                if r.status_code != 404:
                    failures.append(f"cross-tenant PATCH should be 404, got {r.status_code}")
                # 10b-iii: try to create attestation on someone else's target
                r = intruder.post(
                    f"/api/v1/targets/{target_id}/attestations",
                    json={"method": "SELF_ATTESTATION"},
                )
                show("intruder_create_attestation", r)
                if r.status_code != 404:
                    failures.append(
                        f"cross-tenant attestation create should be 404, got {r.status_code}"
                    )

        # 10c: owner access still works.
        r = client.get(f"/api/v1/targets/{target_id}")
        show("owner_get_target", r)
        if r.status_code != 200:
            failures.append(f"owner GET failed: {r.status_code}")

    return _summary(failures)


def _summary(failures: list[str]) -> int:
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    if not failures:
        print("ALL CHECKS PASSED")
        return 0
    print(f"FAILED ({len(failures)}):")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
