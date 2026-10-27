#!/usr/bin/env python3
"""Fetch the vulnerabilities disclosed recently, plus the known-exploited catalog.

Sources:
  GitHub Global Advisory DB  - ecosystem-aware, carries exact vulnerable version ranges
  CISA KEV                   - the subset being exploited in the wild right now
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GH_API = "https://api.github.com"
UA = "vuln-radar (local security triage)"

# GitHub advisory ecosystems worth querying, keyed by the names inventory.py emits.
ECOSYSTEMS = ["npm", "pip", "rubygems", "maven", "composer", "nuget", "go", "rust",
              "erlang", "actions", "pub", "swift", "other"]


def http_json(url, timeout=45):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def have_gh():
    if not shutil.which("gh"):
        return False
    try:
        return subprocess.run(["gh", "auth", "status"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def gh_paginate(path, limit_pages=40):
    """gh handles the cursor pagination and auth for us."""
    cmd = ["gh", "api", "--paginate", "--slurp", path]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"gh api failed: {exc}") from exc
    if out.returncode != 0:
        raise RuntimeError(f"gh api failed: {out.stderr.strip()[:400]}")
    pages = json.loads(out.stdout or "[]")
    rows = []
    for page in pages[:limit_pages]:
        rows.extend(page if isinstance(page, list) else [page])
    return rows


def http_paginate(path, max_pages=10):
    """Unauthenticated fallback. 60 requests/hour, so keep the page count small."""
    rows = []
    url = f"{GH_API}{path}"
    for _ in range(max_pages):
        req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                   "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            batch = json.loads(resp.read().decode("utf-8", "replace"))
            link = resp.headers.get("Link", "")
        rows.extend(batch)
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
        if not nxt or not batch:
            break
        url = nxt.group(1)
    return rows


def normalize(adv):
    affected = []
    for entry in adv.get("vulnerabilities") or []:
        package = (entry or {}).get("package") or {}
        name = package.get("name")
        if not name:
            continue
        fix = entry.get("first_patched_version")
        if isinstance(fix, dict):
            fix = fix.get("identifier")
        affected.append({
            "ecosystem": (package.get("ecosystem") or "other").lower(),
            "name": name,
            "range": entry.get("vulnerable_version_range") or "",
            "fixed": fix,
        })
    epss = adv.get("epss") or {}
    return {
        "id": adv.get("ghsa_id"),
        "cve": adv.get("cve_id"),
        "severity": (adv.get("severity") or "unknown").lower(),
        "cvss": ((adv.get("cvss") or {}).get("score")),
        "epss": epss.get("percentage"),
        "published": (adv.get("published_at") or "")[:10],
        "summary": (adv.get("summary") or "").strip(),
        "url": adv.get("html_url"),
        "cwes": [c.get("cwe_id") for c in (adv.get("cwes") or []) if c.get("cwe_id")],
        "affected": affected,
    }


def fetch_advisories(ecosystems, days, severities, use_gh):
    since = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
    advisories, errors = {}, []
    for eco in ecosystems:
        query = f"/advisories?per_page=100&type=reviewed&published=%3E%3D{since}&ecosystem={eco}"
        if severities:
            query += "&severity=" + ",".join(severities)
        try:
            rows = gh_paginate(query) if use_gh else http_paginate(query)
        except (RuntimeError, urllib.error.URLError, OSError, ValueError) as exc:
            errors.append(f"{eco}: {exc}")
            continue
        for adv in rows:
            if not isinstance(adv, dict) or adv.get("withdrawn_at"):
                continue
            norm = normalize(adv)
            if norm["id"]:
                advisories[norm["id"]] = norm
    return list(advisories.values()), errors, since


def fetch_kev():
    data = http_json(KEV_URL, timeout=60)
    rows = []
    for entry in data.get("vulnerabilities") or []:
        rows.append({
            "cve": entry.get("cveID"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "name": entry.get("vulnerabilityName"),
            "added": entry.get("dateAdded"),
            "due": entry.get("dueDate"),
            "ransomware": entry.get("knownRansomwareCampaignUse") == "Known",
            "action": entry.get("requiredAction"),
        })
    return rows, data.get("catalogVersion")


def main():
    ap = argparse.ArgumentParser(description="Fetch recent advisories + CISA KEV")
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--ecosystems", nargs="*", default=None)
    ap.add_argument("--severity", nargs="*", default=None,
                    choices=["low", "medium", "high", "critical"])
    ap.add_argument("--graph", help="restrict ecosystems to those present in this graph")
    ap.add_argument("--out", required=True)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    ecosystems = args.ecosystems
    if not ecosystems and args.graph:
        graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
        present = {n.get("ecosystem") for n in graph.get("nodes", []) if n.get("kind") == "package"}
        ecosystems = [e for e in ECOSYSTEMS if e in present]
    ecosystems = ecosystems or ECOSYSTEMS

    use_gh = have_gh()
    advisories, errors, since = fetch_advisories(ecosystems, args.days, args.severity, use_gh)

    kev, kev_version = [], None
    try:
        kev, kev_version = fetch_kev()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        errors.append(f"kev: {exc}")

    payload = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "window_days": args.days,
        "published_since": since,
        "ecosystems": ecosystems,
        "auth": "gh" if use_gh else "anonymous",
        "advisories": advisories,
        "kev": kev,
        "kev_catalog": kev_version,
        "errors": errors,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload), encoding="utf-8")

    if not args.quiet:
        by_sev = {}
        for adv in advisories:
            by_sev[adv["severity"]] = by_sev.get(adv["severity"], 0) + 1
        order = ["critical", "high", "medium", "low", "unknown"]
        sev = ", ".join(f"{s}={by_sev[s]}" for s in order if s in by_sev)
        print(f"advisories: {len(advisories)} published since {since} ({sev or 'none'})")
        print(f"ecosystems queried: {', '.join(ecosystems)}  [auth: {payload['auth']}]")
        print(f"kev catalog: {len(kev)} known-exploited CVEs (version {kev_version})")
        if errors:
            print("warnings:")
            for err in errors[:8]:
                print(f"  - {err}")
        if not use_gh:
            print("note: `gh auth login` raises the advisory rate limit from 60/hr to 5000/hr")
    return 0


if __name__ == "__main__":
    sys.exit(main())
