#!/usr/bin/env python3
"""Match the advisory feed against the machine graph and rank by whether action is needed.

Two classes of result, never conflated:
  finding - a package node whose resolved version falls inside a published vulnerable range
  lead    - a host/OS/image node that shares a name with a known-exploited CVE; no version
            range exists in KEV, so these need a human to confirm
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vercmp import cmp_version, highest, in_range, lowest, parse_version, selftest  # noqa: E402

STOPWORDS ={"and", "the", "for", "server", "service", "software", "products", "product",
             "system", "systems", "manager", "suite", "platform", "plugin", "core", "web",
             "data", "cloud", "enterprise", "edition", "framework", "library", "multiple"}


def norm_name(ecosystem, name):
    name = (name or "").strip()
    if ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def product_tokens(*values):
    tokens = set()
    for value in values:
        for token in re.split(r"[^A-Za-z0-9]+", (value or "").lower()):
            if len(token) >= 4 and token not in STOPWORDS:
                tokens.add(token)
    return tokens


class Index:
    def __init__(self, graph):
        self.nodes = {n["id"]: n for n in graph["nodes"]}
        self.by_pkg = {}
        self.edges_to = {}
        for node in graph["nodes"]:
            if node["kind"] == "package":
                key = (node["ecosystem"], norm_name(node["ecosystem"], node["name"]))
                self.by_pkg.setdefault(key, []).append(node)
        for edge in graph["edges"]:
            self.edges_to.setdefault(edge["target"], []).append(edge)

    def consumers(self, node_id):
        """Projects that pull in this node, with how they pull it in."""
        out = []
        for edge in self.edges_to.get(node_id, []):
            project = self.nodes.get(edge["source"])
            if project and project["kind"] == "project":
                out.append((project, edge))
        return out


def reachability(consumers):
    runtime = [c for c in consumers if c[1]["rel"] == "depends_on"]
    ci = [c for c in consumers if c[1]["rel"] == "ci_uses"]
    active = [c for c in consumers
              if (c[0].get("stale_days") is None or c[0]["stale_days"] <= 120)]
    runtime_active = [c for c in runtime
                      if (c[0].get("stale_days") is None or c[0]["stale_days"] <= 120)]
    return {
        "runtime": bool(runtime),
        "ci_only": bool(ci) and not runtime,
        "dev_only": bool(consumers) and not runtime and not ci,
        "active": bool(active),
        "runtime_active": bool(runtime_active),
    }


def rank(severity, kev, reach, confident):
    sev = (severity or "unknown").lower()
    if kev:
        return "P0", "listed in CISA KEV — exploited in the wild"
    if sev == "critical" and reach["runtime_active"]:
        return "P0", "critical severity in a runtime dependency of an active project"
    if sev in ("critical", "high") and reach["runtime"]:
        band = "P1" if reach["active"] else "P2"
        why = ("high/critical in a runtime dependency" if reach["active"]
               else "high/critical, but the project looks dormant")
        return band, why
    if sev in ("critical", "high"):
        where = "CI workflow" if reach["ci_only"] else "dev-only dependency"
        return "P2", f"high/critical, reached only through a {where}"
    if sev == "medium" and reach["runtime_active"]:
        return "P2", "medium severity in a runtime dependency"
    return "P3", f"{sev} severity, limited exposure"


def dependabot_state(coverage, project, package):
    """Whether Dependabot has this one covered, and how far it has got.

    An open PR means the user can merge instead of fixing. An alert with no PR means
    GitHub flagged it but nothing is coming — the work is still theirs.
    """
    slug = project.get("github")
    if not slug:
        return {"state": "no-repo" if not project.get("git_remote") else "not-github"}
    repo = (coverage or {}).get(slug)
    if not repo or not repo.get("readable"):
        # No live lookup (it is opt-in): say what is true of any GitHub repo.
        return {"state": "github", "repo": slug}
    key = package.lower()
    pr = (repo.get("prs") or {}).get(key)
    if pr:
        return {"state": "pr", "repo": slug, "number": pr["number"], "url": pr["url"]}
    ghsa = (repo.get("alerts") or {}).get(key)
    if ghsa:
        return {"state": "alert", "repo": slug, "ghsa": [g for g in ghsa if g][:3]}
    return {"state": "none", "repo": slug}


def fix_command(ecosystem, project, name, fixed):
    manifests = project.get("manifests") or []
    target = f"{name}@{fixed}" if fixed else name
    if ecosystem == "npm":
        if "pnpm-lock.yaml" in manifests:
            return f"pnpm up {target}" if fixed else f"pnpm up {name} --latest"
        if "yarn.lock" in manifests:
            return f"yarn up {target}"
        if "bun.lock" in manifests or "bun.lockb" in manifests:
            return f"bun update {target}"
        return f"npm install {target}" if fixed else f"npm audit fix"
    if ecosystem == "pip":
        if "poetry.lock" in manifests:
            return f"poetry update {name}"
        if "uv.lock" in manifests:
            return f"uv lock --upgrade-package {target}"
        return f"pip install -U '{name}=={fixed}'" if fixed else f"pip install -U {name}"
    if ecosystem == "rust":
        return f"cargo update -p {name}" + (f" --precise {fixed}" if fixed else "")
    if ecosystem == "go":
        return f"go get {name}@{fixed}" if fixed else f"go get -u {name}"
    if ecosystem == "rubygems":
        return f"bundle update {name}"
    if ecosystem == "composer":
        return f"composer require {name}:^{fixed}" if fixed else f"composer update {name}"
    if ecosystem == "maven":
        return f"bump {name} to {fixed} in pom.xml" if fixed else f"bump {name} in pom.xml"
    if ecosystem == "actions":
        return f"pin {name} to {fixed} in .github/workflows" if fixed else f"update {name}"
    return f"upgrade {target}"


def match_advisories(index, intel, kev_by_cve):
    coverage = intel.get("coverage") or {}
    findings = []
    for adv in intel.get("advisories", []):
        for affected in adv.get("affected", []):
            eco = affected["ecosystem"]
            key = (eco, norm_name(eco, affected["name"]))
            for node in index.by_pkg.get(key, []):
                if not in_range(node["version"], affected["range"]):
                    continue
                consumers = index.consumers(node["id"])
                if not consumers:
                    continue
                reach = reachability(consumers)
                confident = bool(node.get("resolved", True))
                kev = kev_by_cve.get(adv.get("cve") or "")
                band, why = rank(adv["severity"], bool(kev), reach, confident)
                if not confident and band == "P0" and not kev:
                    band, why = "P1", why + " (version inferred from a declared range)"
                projects = []
                for project, edge in consumers:
                    projects.append({
                        "path": project["path"],
                        "name": project["name"],
                        "rel": edge["rel"],
                        "direct": bool(edge.get("direct")),
                        "stale_days": project.get("stale_days"),
                        "fix": fix_command(eco, project, affected["name"], affected.get("fixed")),
                        "dependabot": dependabot_state(coverage, project, affected["name"]),
                        "build": project.get("build_policy"),
                    })
                findings.append({
                    "type": "finding",
                    "key": f"{adv['id']}|{eco}:{affected['name']}@{node['version']}",
                    "band": band, "why": why,
                    "advisory": adv["id"], "cve": adv.get("cve"),
                    "severity": adv["severity"], "cvss": adv.get("cvss"),
                    "epss": adv.get("epss"), "published": adv.get("published"),
                    "summary": adv.get("summary"), "url": adv.get("url"),
                    "kev": bool(kev), "kev_due": (kev or {}).get("due"),
                    "ransomware": bool((kev or {}).get("ransomware")),
                    "ecosystem": eco, "package": affected["name"],
                    "installed": node["version"], "vulnerable_range": affected["range"],
                    "fixed_version": affected.get("fixed"),
                    "confident": confident,
                    "reach": reach,
                    "projects": sorted(projects, key=lambda p: p["path"]),
                })
    return findings


def match_kev_leads(index, kev_rows, days):
    """KEV carries no version ranges, so host-layer hits are leads for a human to confirm."""
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
    host_nodes = [n for n in index.nodes.values()
                  if n["kind"] in ("host_package", "runtime", "os", "image")]
    leads = []
    for row in kev_rows:
        if (row.get("added") or "") < cutoff:
            continue
        tokens = product_tokens(row.get("product"), row.get("vendor"))
        if not tokens:
            continue
        hits = []
        for node in host_nodes:
            name_tokens = product_tokens(node["name"])
            if name_tokens & tokens:
                hits.append({"id": node["id"], "kind": node["kind"], "name": node["name"],
                             "version": node.get("version"),
                             "manager": node.get("manager")})
        if hits:
            leads.append({
                "type": "lead", "key": f"kev|{row['cve']}",
                "band": "P1", "why": "known-exploited CVE naming software installed here; "
                                     "KEV has no version range, so confirm your version is in scope",
                "cve": row["cve"], "kev": True, "kev_due": row.get("due"),
                "ransomware": bool(row.get("ransomware")),
                "added": row.get("added"), "vendor": row.get("vendor"),
                "product": row.get("product"), "summary": row.get("name"),
                "action": row.get("action"),
                "url": f"https://nvd.nist.gov/vuln/detail/{row['cve']}",
                "matches": sorted(hits, key=lambda h: h["id"])[:12],
                "confident": False,
            })
    return leads


def osv_fix_target(vuln, package, installed):
    """Smallest published fix above the installed version, across the affected ranges."""
    candidates = []
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name", package) != package:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    candidates.append(fixed)
    current = parse_version(installed)
    higher = [c for c in candidates
              if parse_version(c) and current and cmp_version(parse_version(c), current) > 0]
    return lowest(higher) or highest(candidates)


def ingest_osv(path, index, coverage=None):
    """Merge `osv-scanner --format json`: the full advisory history, not just the window."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    eco_map = {"npm": "npm", "pypi": "pip", "rubygems": "rubygems", "maven": "maven",
               "packagist": "composer", "crates.io": "rust", "go": "go", "pub": "pub",
               "nuget": "nuget", "hex": "erlang", "github actions": "actions"}
    findings = []
    for result in data.get("results", []) or []:
        source = ((result.get("source") or {}).get("path")) or ""
        for entry in result.get("packages", []) or []:
            pkg = entry.get("package") or {}
            eco = eco_map.get((pkg.get("ecosystem") or "").lower().split(":")[0], "other")
            name, version = pkg.get("name"), pkg.get("version")
            if not name or not version:
                continue

            worst = {}
            for group in entry.get("groups", []) or []:
                try:
                    score = float(group.get("max_severity") or "")
                except (TypeError, ValueError):
                    score = None
                for vid in group.get("ids") or []:
                    worst[vid] = score

            node_id = f"pkg:{eco}:{name}@{version}"
            consumers = index.consumers(node_id)
            reach = reachability(consumers) if consumers else {
                "runtime": True, "ci_only": False, "dev_only": False,
                "active": True, "runtime_active": True}

            for vuln in entry.get("vulnerabilities", []) or []:
                vid = vuln.get("id")
                aliases = [vid] + list(vuln.get("aliases") or [])
                score = worst.get(vid)
                sev = ("critical" if score and score >= 9 else "high" if score and score >= 7
                       else "medium" if score and score >= 4 else "low" if score else "unknown")
                malware = str(vid).startswith("MAL-")
                band, why = rank("critical" if malware else sev, False, reach, True)
                if malware:
                    band, why = "P0", "MALICIOUS PACKAGE advisory (MAL-*) — treat as compromise"
                ghsa = next((a for a in aliases if str(a).startswith("GHSA-")), None)
                fixed = osv_fix_target(vuln, name, version)
                findings.append({
                    "type": "finding", "source": "osv-scanner",
                    "key": f"{vid}|{eco}:{name}@{version}",
                    "band": band, "why": why,
                    "advisory": ghsa or vid,
                    "cve": next((a for a in aliases if str(a).startswith("CVE-")), None),
                    "aliases": aliases, "severity": sev, "cvss": score,
                    "malware": malware,
                    "summary": (vuln.get("summary") or vuln.get("details") or "")[:400],
                    "url": f"https://osv.dev/vulnerability/{vid}",
                    "kev": False, "ecosystem": eco, "package": name, "installed": version,
                    "vulnerable_range": "see advisory", "fixed_version": fixed,
                    # Dependabot draws on the GitHub Advisory DB and needs a version to
                    # bump to; without a GHSA id or a published fix it cannot act.
                    "dependabot_reachable": bool(ghsa) and bool(fixed) and not malware,
                    "confident": True, "reach": reach,
                    "projects": ([{"path": project["path"], "name": project["name"],
                                   "rel": edge["rel"], "direct": bool(edge.get("direct")),
                                   "stale_days": project.get("stale_days"),
                                   "fix": fix_command(eco, project, name, fixed),
                                   "dependabot": dependabot_state(coverage, project, name),
                                   "build": project.get("build_policy")}
                                  for project, edge in consumers]
                                 or [{"path": source, "name": Path(source).parent.name,
                                      "rel": "depends_on", "direct": False,
                                      "stale_days": None,
                                      "fix": f"upgrade {name} (currently {version})",
                                      "dependabot": {"state": "unknown"}}]),
                })
    return findings


def code_alerts(index):
    """Things found by reading the code itself, not by matching an advisory."""
    out = []
    for node in index.nodes.values():
        if node.get("kind") != "project":
            continue
        for risky in node.get("risky_scripts") or []:
            out.append({
                "kind": "lifecycle-script",
                "project": node.get("path"),
                "name": node.get("name"),
                "hook": risky["hook"],
                "command": risky["command"],
                "why": risky["why"],
            })
    return out


def install_exposure(index):
    """Which projects can actually execute dependency code at install time."""
    blocked, running = [], []
    for node in index.nodes.values():
        if node.get("kind") != "project":
            continue
        policy = node.get("build_policy")
        if not policy:
            continue
        row = {"path": node.get("path"), "name": node.get("name"),
               "manager": policy.get("manager"), "why": policy.get("why"),
               "allowed": policy.get("allowed") or [],
               "packages": node.get("install_script_packages") or []}
        (blocked if policy.get("blocked") else running).append(row)
    blocked.sort(key=lambda r: r["name"] or "")
    running.sort(key=lambda r: -len(r["packages"]))
    return {"blocked": blocked, "running": running}


def install_script_summary(index):
    total = {}
    for node in index.nodes.values():
        if node.get("kind") != "project":
            continue
        for entry in node.get("install_script_packages") or []:
            total.setdefault(entry, []).append(node.get("path"))
    return total


def dedupe(findings):
    best = {}
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    for finding in findings:
        key = finding["key"]
        current = best.get(key)
        if current is None or order[finding["band"]] < order[current["band"]]:
            best[key] = finding
    return list(best.values())


def main():
    ap = argparse.ArgumentParser(description="Match advisories against the machine graph")
    ap.add_argument("--graph")
    ap.add_argument("--intel")
    ap.add_argument("--osv-results", help="osv-scanner --format json output to merge")
    ap.add_argument("--state", help="previous findings.json, for the new-since-last-run diff")
    ap.add_argument("--kev-days", type=int, default=90,
                    help="window for host-layer KEV leads")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not (args.graph and args.intel and args.out):
        ap.error("--graph, --intel and --out are required unless --selftest")

    graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
    intel = json.loads(Path(args.intel).read_text(encoding="utf-8"))
    index = Index(graph)
    kev_rows = intel.get("kev") or []
    kev_by_cve = {row["cve"]: row for row in kev_rows if row.get("cve")}

    findings = match_advisories(index, intel, kev_by_cve)
    if args.osv_results:
        findings += ingest_osv(args.osv_results, index, intel.get("coverage") or {})
    findings = dedupe(findings)
    leads = match_kev_leads(index, kev_rows, args.kev_days)

    previous = set()
    if args.state and Path(args.state).is_file():
        try:
            old = json.loads(Path(args.state).read_text(encoding="utf-8"))
            previous = {f["key"] for f in old.get("findings", []) + old.get("leads", [])}
        except (OSError, ValueError):
            previous = set()
    for item in findings + leads:
        item["new"] = bool(previous) and item["key"] not in previous

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(key=lambda f: (order[f["band"]], -(f.get("cvss") or 0), f["package"]))
    leads.sort(key=lambda l: (l.get("added") or ""), reverse=True)

    counts = {band: sum(1 for f in findings if f["band"] == band) for band in order}
    alerts = code_alerts(index)
    malware = [f for f in findings if f.get("malware")]
    # A MAL-* match is serious, but "declared in a lockfile of a dormant project" and
    # "unpacked in node_modules right now" are very different situations. Say which.
    for item in malware:
        for project in item["projects"]:
            unpacked = Path(project["path"], "node_modules", item["package"]).exists()
            project["installed_on_disk"] = unpacked
        item["installed_on_disk"] = any(p.get("installed_on_disk")
                                        for p in item["projects"])
        item["dormant_days"] = min(
            [p["stale_days"] for p in item["projects"] if p.get("stale_days") is not None],
            default=None)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "graph_generated_at": graph.get("generated_at"),
        "intel": {k: intel.get(k) for k in
                  ("fetched_at", "window_days", "published_since", "ecosystems", "auth",
                   "kev_catalog", "errors")},
        "graph_stats": graph.get("stats"),
        "counts": counts,
        "advisories_considered": len(intel.get("advisories", [])),
        "had_previous_state": bool(previous),
        "findings": findings,
        "leads": leads,
        "alerts": alerts,
        "malware": malware,
        "install_scripts": install_script_summary(index),
        "install_exposure": install_exposure(index),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload), encoding="utf-8")

    if not args.quiet:
        print(f"findings: {len(findings)} "
              f"(P0={counts['P0']} P1={counts['P1']} P2={counts['P2']} P3={counts['P3']})")
        print(f"kev host leads: {len(leads)} (unverified, need a version check)")
        installs = install_script_summary(index)
        if malware:
            print(f"!! MALICIOUS PACKAGES: {len(malware)} MAL-* advisory match(es)")
        if alerts:
            print(f"!! suspicious lifecycle scripts: {len(alerts)}")
        exposure = install_exposure(index)
        if not malware and not alerts:
            print(f"malicious-code check: clean — {len(exposure['blocked'])} project(s) "
                  f"block install scripts, {len(exposure['running'])} allow them "
                  f"({len(installs)} dependency script(s))")
        if previous:
            print(f"new since last run: {sum(1 for f in findings if f['new'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
