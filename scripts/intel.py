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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Node core CVEs carry no package ecosystem, so they never appear in the advisory feeds
# the package matcher uses. Node publishes them with semver ranges of their own.
NODE_CORE_URL = ("https://raw.githubusercontent.com/nodejs/security-wg"
                 "/main/vuln/core/index.json")
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


def gh_json(path, timeout=60):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout or "null")
    except ValueError:
        return None


def repo_coverage(slug):
    """What Dependabot already knows about this repo.

    An open alert means GitHub is flagging it; an open PR means the fix is one merge
    away. They are different settings — a repo can raise alerts and still open no PRs
    — and that difference decides whether the user has work to do.
    """
    alerts = gh_json(f"repos/{slug}/dependabot/alerts?state=open&per_page=100")
    if alerts is None:
        return {"readable": False, "alerts": {}, "prs": {}}
    by_package = {}
    for alert in alerts:
        name = (((alert or {}).get("dependency") or {}).get("package") or {}).get("name")
        ghsa = ((alert or {}).get("security_advisory") or {}).get("ghsa_id")
        if name:
            by_package.setdefault(name.lower(), []).append(ghsa)

    prs = {}
    try:
        out = subprocess.run(
            ["gh", "pr", "list", "--repo", slug, "--author", "app/dependabot",
             "--state", "open", "--json", "number,title,url", "--limit", "100"],
            capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            for pr in json.loads(out.stdout or "[]"):
                # "Bump undici from 7.25.0 to 7.30.1" / "chore(deps): bump undici ..."
                m = re.search(r"\bbump\s+([^\s]+)\s+from\b", pr.get("title", ""), re.I)
                if m:
                    prs[m.group(1).lower()] = {"number": pr["number"], "url": pr["url"]}
    except (subprocess.SubprocessError, ValueError, OSError):
        pass
    return {"readable": True, "alerts": by_package, "prs": prs}


def fetch_coverage(graph_path):
    """Dependabot state per GitHub repo present in the graph."""
    try:
        graph = json.loads(Path(graph_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    slugs = sorted({n["github"] for n in graph.get("nodes", [])
                    if n.get("kind") == "project" and n.get("github")})
    if not slugs:
        return {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(repo_coverage, slugs))
    return dict(zip(slugs, results))


def fetch_node_core(platform):
    """Node.js runtime advisories, with the ones for other operating systems dropped."""
    data = http_json(NODE_CORE_URL, timeout=45)
    rows = []
    for key, entry in (data or {}).items():
        if not isinstance(entry, dict):
            continue
        envs = [e.lower() for e in (entry.get("affectedEnvironments") or ["all"])]
        if "all" not in envs and platform not in envs:
            continue
        cves = [c for c in (entry.get("cve") or []) if c]
        rows.append({
            "runtime": "node",
            "id": cves[0] if cves else f"nodejs-core-{key}",
            "cve": cves[0] if cves else None,
            "aliases": cves,
            "severity": (entry.get("severity") or "unknown").lower(),
            "vulnerable": entry.get("vulnerable"),
            "patched": entry.get("patched"),
            "summary": (entry.get("description") or entry.get("overview") or "").strip()[:300],
            "url": entry.get("ref") or
                   (f"https://nvd.nist.gov/vuln/detail/{cves[0]}" if cves else None),
            "environments": envs,
        })
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
    ap.add_argument("--dependabot-status", action="store_true",
                    help="look up live Dependabot alerts and PRs per repo (needs gh "
                         "access to each repo; off by default)")
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

    coverage = {}
    if use_gh and args.graph and args.dependabot_status:
        try:
            coverage = fetch_coverage(args.graph)
        except Exception as exc:
            errors.append(f"dependabot coverage: {exc}")

    kev, kev_version = [], None
    try:
        kev, kev_version = fetch_kev()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        errors.append(f"kev: {exc}")

    runtime_advisories = []
    try:
        runtime_advisories = fetch_node_core(sys.platform)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        errors.append(f"node core: {exc}")

    payload = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "window_days": args.days,
        "published_since": since,
        "ecosystems": ecosystems,
        "auth": "gh" if use_gh else "anonymous",
        "advisories": advisories,
        "kev": kev,
        "kev_catalog": kev_version,
        "runtime_advisories": runtime_advisories,
        "platform": sys.platform,
        "coverage": coverage,
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
        print(f"node core: {len(runtime_advisories)} runtime advisories for {sys.platform}")
        if coverage:
            readable = [v for v in coverage.values() if v["readable"]]
            alerting = sum(1 for v in readable if v["alerts"])
            prs = sum(len(v["prs"]) for v in readable)
            print(f"dependabot: {len(readable)}/{len(coverage)} repos readable, "
                  f"{alerting} with open alerts, {prs} open PR(s)")
        if errors:
            print("warnings:")
            for err in errors[:8]:
                print(f"  - {err}")
        if not use_gh:
            print("note: `gh auth login` raises the advisory rate limit from 60/hr to 5000/hr")
    return 0


if __name__ == "__main__":
    sys.exit(main())
