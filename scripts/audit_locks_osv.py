"""Local OSV equivalent of the CI pip-audit gate (Windows-safe).

pip-audit's `-r` mode resolves the locked requirements into a pip
environment, which fails on Windows because uvloop has no Windows
artifacts. This queries OSV — the same advisory database pip-audit uses
— directly with the exact locked pins.
"""

import json
import re
import sys
import urllib.request


def pins(path: str) -> list[tuple[str, str]]:
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def audit(path: str) -> int:
    entries = pins(path)
    queries = [
        {"package": {"name": n.lower(), "ecosystem": "PyPI"}, "version": v}
        for n, v in entries
    ]
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        results = json.load(resp)["results"]
    hits = []
    for (name, version), r in zip(entries, results):
        for vuln in r.get("vulns", []):
            hits.append((name, version, vuln["id"]))
    print(f"{path}: {len(entries)} pins, {len(hits)} OSV advisories")
    for name, version, vuln_id in hits:
        print(f"   {name}=={version}: {vuln_id}")
    return len(hits)


if __name__ == "__main__":
    total = 0
    for lock in sys.argv[1:]:
        total += audit(lock)
    sys.exit(0 if total == 0 else 1)
