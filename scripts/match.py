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
from vercmp import (cmp_version, highest, in_range, lowest,  # noqa: E402
                    node_affected, parse_version, satisfies, selftest)

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
        self.projects_by_path = {}
        self.edges_to = {}
        for node in graph["nodes"]:
            if node["kind"] == "package":
                key = (node["ecosystem"], norm_name(node["ecosystem"], node["name"]))
                self.by_pkg.setdefault(key, []).append(node)
            elif node["kind"] == "project" and node.get("path"):
                self.projects_by_path[node["path"]] = node
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

    def project_at(self, path):
        return self.projects_by_path.get(path)

    def package_node(self, ecosystem, name, version):
        """The graph node for a package osv-scanner reported, or None.

        The ids do not match as strings: osv-scanner reports a package's own tag, and
        a Composer tag carries a leading `v`.
        """
        want = parse_version(version)
        for node in self.by_pkg.get((ecosystem, norm_name(ecosystem, name)), []):
            if parse_version(node.get("version")) == want:
                return node
        return None


def reachability(consumers):
    runtime = [c for c in consumers if c[1]["rel"] == "depends_on"]
    ci = [c for c in consumers if c[1]["rel"] == "ci_uses"]
    active = [c for c in consumers
              if (c[0].get("stale_days") is None or c[0]["stale_days"] <= 120)]
    runtime_active = [c for c in runtime
                      if (c[0].get("stale_days") is None or c[0]["stale_days"] <= 120)]
    def state(c):
        return c[0].get("install_state") or {}
    on_disk = [c for c in consumers if state(c).get("present")]
    unknown = [c for c in consumers if not state(c).get("known")]
    return {
        "runtime": bool(runtime),
        "ci_only": bool(ci) and not runtime,
        "dev_only": bool(consumers) and not runtime and not ci,
        "active": bool(active),
        "runtime_active": bool(runtime_active),
        "on_disk": bool(on_disk),
        # Every consumer is an ecosystem we can answer for, and none of them has the tree
        # installed: the vulnerable version is a lockfile line, not code on this machine.
        "not_installed": bool(consumers) and not on_disk and not unknown,
    }


SOFTEN = {"P0": "P1", "P1": "P2", "P2": "P3", "P3": "P3"}


def project_band(band, project, pinned):
    """The band for one project, not for the advisory as a whole.

    A package can be installed in one checkout and merely pinned in twenty others. Ranking
    every one of them by the worst case is what buries the projects you actually work in.
    """
    if pinned:
        return band
    state = project.get("install_state") or {}
    if not state.get("known") or state.get("present"):
        return band
    stale = project.get("stale_days")
    if stale is not None and stale > 120:
        return "P3"
    return SOFTEN[band]


def rank(severity, kev, reach, confident):
    if kev:
        return "P0", "listed in CISA KEV — exploited in the wild"
    band, why = severity_band(severity, reach)
    if reach["not_installed"]:
        # Nothing to reach until someone installs. Softened rather than dropped, because
        # the next `npm install` in that checkout brings the vulnerable version back.
        band = "P3" if not reach["active"] else SOFTEN[band]
        why += "; dependencies are not installed here"
    return band, why


def severity_band(severity, reach):
    sev = (severity or "unknown").lower()
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
                        "deps_installed": (project.get("install_state") or {}),
                        "band": project_band(band, project, bool(kev)),
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


RUNTIME_BAND = {"critical": "P0", "high": "P1", "medium": "P2",
                "low": "P3", "unknown": "P3"}


def node_fix_target(patched, version):
    """The version this release line was fixed in, as written: `^22.23.2` -> `22.23.2`."""
    target = parse_version(version)
    if not target or not target[0]:
        return None
    for part in str(patched or "").split("||"):
        cleaned = part.strip().lstrip("^~>=< ")
        parsed = parse_version(cleaned)
        if parsed and parsed[0] and parsed[0][0] == target[0][0]:
            return cleaned
    return None


EXACT_PIN = {".nvmrc", ".node-version", ".python-version", ".ruby-version"}


def runtime_is_exact(node):
    """Only match a runtime version that something will actually run.

    `engines` holds ranges — `>=20` reduces to the string "20" — and a bare major in
    .nvmrc means "newest of that line". Reading either as a literal version invents an
    ancient release nobody has, and then matches every advisory fixed since.
    """
    source = node.get("source")
    if source == "installed":
        return True
    if source not in EXACT_PIN:
        return False
    parsed = parse_version(node.get("version"))
    return bool(parsed and len(parsed[0]) >= 3)


def match_runtimes(index, intel, kev_by_cve):
    """Version-match the runtimes themselves.

    Node core CVEs carry no package ecosystem, so the advisory matcher never sees them:
    without this the interpreter is inventoried and then never actually checked.
    """
    advisories = intel.get("runtime_advisories") or []
    if not advisories:
        return []
    findings = []
    for node in index.nodes.values():
        if node.get("kind") != "runtime" or not node.get("version"):
            continue
        if not runtime_is_exact(node):
            continue
        name = (node.get("name") or "").lower()
        # "installed" is what actually runs; a pinned version is what a checkout asks for.
        installed = node.get("source") == "installed"
        projects = [{"path": p["path"], "name": p["name"],
                     "stale_days": p.get("stale_days")}
                    for p, _ in index.consumers(node["id"])]
        for adv in advisories:
            if adv.get("runtime") != name:
                continue
            if not node_affected(node["version"], adv.get("vulnerable"), adv.get("patched")):
                continue
            kev = kev_by_cve.get(adv.get("cve") or "")
            severity = (adv.get("severity") or "unknown").lower()
            band = "P0" if kev else RUNTIME_BAND.get(severity, "P3")
            if kev:
                why = "listed in CISA KEV — exploited in the wild"
            elif installed:
                why = f"{severity} severity in the {name} you have installed"
            else:
                band = SOFTEN[band]
                why = f"{severity} severity in a pinned {name} version, not the one running"
            fixed = node_fix_target(adv.get("patched"), node["version"])
            findings.append({
                "type": "runtime",
                "key": f"{adv['id']}|{name}@{node['version']}|{node.get('source')}",
                "band": band, "why": why,
                "advisory": adv["id"], "cve": adv.get("cve"),
                "aliases": adv.get("aliases") or [],
                "severity": severity, "kev": bool(kev),
                "summary": adv.get("summary"), "url": adv.get("url"),
                "ecosystem": "runtime", "package": name,
                "installed": node["version"], "fixed_version": fixed,
                "vulnerable_range": adv.get("vulnerable"),
                "source": node.get("source"), "running": installed,
                "environments": adv.get("environments") or ["all"],
                "projects": projects,
                "fix": (f"nvm install {fixed} && nvm alias default {fixed}"
                        if fixed and installed else
                        f"pin {name} >= {fixed}" if fixed else None),
                "confident": True,
            })
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(key=lambda f: (order[f["band"]], not f["running"], f["advisory"]))
    return findings


def resolve_node(spec, available):
    """The node version a project would actually run.

    An exact pin is taken at its word even when it is not installed here — it is what the
    checkout asks for. A range resolves to the newest installed version that satisfies it.
    """
    exact = parse_version(spec)
    if exact and len(exact[0]) >= 3 and not re.search(r"[<>=^~|x*\s]", str(spec)):
        return str(spec).lstrip("v")
    best = None
    for version in available or []:
        if satisfies(version, spec) and (best is None or
                                         cmp_version(parse_version(version),
                                                     parse_version(best)) > 0):
            best = version
    return best


def match_project_runtimes(index, intel, graph):
    """Node advisories against the version each backend project resolves to.

    Only projects node actually runs: a front end declares engines.node for its build
    toolchain, and a core CVE in that interpreter never reaches what it ships.
    """
    advisories = [a for a in (intel.get("runtime_advisories") or [])
                  if a.get("runtime") == "node"]
    if not advisories:
        return []
    available = graph.get("node_versions") or []
    out = []
    for node in index.nodes.values():
        if node.get("kind") != "project" or not node.get("node_role"):
            continue
        spec = node.get("node_requires")
        if not spec:
            continue
        resolved = resolve_node(spec, available)
        if not resolved:
            out.append({
                "type": "project_runtime", "key": f"node-unsatisfied|{node['path']}",
                "band": "P3", "path": node["path"], "name": node["name"],
                "role": node["node_role"], "requires": spec,
                "requires_from": node.get("node_requires_from"),
                "resolved": None, "advisories": [],
                "why": f"no node installed here satisfies {spec}",
            })
            continue
        hits = [a for a in advisories
                if node_affected(resolved, a.get("vulnerable"), a.get("patched"))]
        if not hits:
            continue
        worst = min((RUNTIME_BAND.get(a["severity"], "P3") for a in hits), default="P3")
        fixed = node_fix_target(
            max(hits, key=lambda a: a.get("patched") or "").get("patched"), resolved)
        out.append({
            "type": "project_runtime",
            "key": f"node|{node['path']}@{resolved}",
            # One band softer than the interpreter that is running: this is the version
            # the project asks for, and a managed host may patch it independently.
            "band": SOFTEN[worst],
            "path": node["path"], "name": node["name"], "role": node["node_role"],
            "requires": spec, "requires_from": node.get("node_requires_from"),
            "resolved": resolved, "fixed_version": fixed,
            "stale_days": node.get("stale_days"),
            "why": f"runs on node {resolved}, which {len(hits)} core advisories affect",
            "advisories": sorted(
                ({"id": a["id"], "cve": a.get("cve"), "severity": a["severity"],
                  "summary": a.get("summary"), "url": a.get("url"),
                  "fixed": node_fix_target(a.get("patched"), resolved)} for a in hits),
                key=lambda a: ({"critical": 0, "high": 1, "medium": 2, "low": 3}
                               .get(a["severity"], 4), a["id"])),
        })
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    out.sort(key=lambda r: (order[r["band"]], -len(r["advisories"]), r["name"]))
    return out


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


def osv_projects(consumers, owner, coverage, source, eco, name, version, fixed,
                 band, malware):
    """Which projects an osv-scanner hit belongs to.

    A transitive package has no node of its own, so it is attributed to the project
    that owns the lockfile, never to the lockfile's own path: that path is not a
    project and counting it as one reports more projects affected than exist.
    """
    pairs = consumers or ([(owner, {"rel": "depends_on", "direct": False})] if owner else [])
    if pairs:
        return [{"path": project["path"], "name": project["name"],
                 "rel": edge["rel"], "direct": bool(edge.get("direct")),
                 "stale_days": project.get("stale_days"),
                 "deps_installed": project.get("install_state") or {},
                 "band": project_band(band, project, malware),
                 "fix": fix_command(eco, project, name, fixed),
                 "dependabot": dependabot_state(coverage, project, name),
                 "build": project.get("build_policy")}
                for project, edge in pairs]
    directory = str(Path(source).parent) if source else ""
    return [{"path": directory, "name": Path(directory).name if directory else name,
             "rel": "depends_on", "direct": False, "stale_days": None,
             "fix": f"upgrade {name} (currently {version})",
             "dependabot": {"state": "unknown"}}]


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

            node = index.package_node(eco, name, version)
            consumers = index.consumers(node["id"]) if node else []
            # osv-scanner resolves transitive dependencies the manifest never names, so
            # a package with no node of its own belongs to the project that owns the
            # file it was found in.
            owner = index.project_at(str(Path(source).parent)) if source else None
            # Key on the graph's spelling of the version so the same advisory from the
            # advisory window and from osv-scanner collapses to one finding.
            installed = node["version"] if node else version
            if consumers:
                reach = reachability(consumers)
            elif owner:
                reach = reachability([(owner, {"rel": "depends_on", "direct": False})])
            else:
                reach = {"runtime": True, "ci_only": False, "dev_only": False,
                         "active": True, "runtime_active": True,
                         "on_disk": True, "not_installed": False}

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
                    "key": f"{vid}|{eco}:{name}@{installed}",
                    "band": band, "why": why,
                    "advisory": ghsa or vid,
                    "cve": next((a for a in aliases if str(a).startswith("CVE-")), None),
                    "aliases": aliases, "severity": sev, "cvss": score,
                    "malware": malware,
                    "summary": (vuln.get("summary") or vuln.get("details") or "")[:400],
                    "url": f"https://osv.dev/vulnerability/{vid}",
                    "kev": False, "ecosystem": eco, "package": name, "installed": installed,
                    "vulnerable_range": "see advisory", "fixed_version": fixed,
                    # Dependabot draws on the GitHub Advisory DB and needs a version to
                    # bump to; without a GHSA id or a published fix it cannot act.
                    "dependabot_reachable": bool(ghsa) and bool(fixed) and not malware,
                    "confident": True, "reach": reach,
                    "projects": osv_projects(consumers, owner, coverage, source, eco,
                                             name, version, fixed, band, malware),
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


OSV_FIXTURE = {
    "nodes": [
        {"id": "proj:/p", "kind": "project", "path": "/p", "name": "p",
         "manifests": ["requirements.txt"], "install_state": {"known": True, "present": True}},
        {"id": "pkg:composer:laravel/framework@12.67.0", "kind": "package",
         "ecosystem": "composer", "name": "laravel/framework", "version": "12.67.0"},
        {"id": "pkg:pip:requests@2.25.1", "kind": "package",
         "ecosystem": "pip", "name": "requests", "version": "2.25.1"},
    ],
    "edges": [{"source": "proj:/p", "target": "pkg:composer:laravel/framework@12.67.0",
               "rel": "depends_on", "direct": True}],
}


def selftest_match():
    """The two ways an osv-scanner hit used to lose the project it belongs to."""
    index = Index(OSV_FIXTURE)
    cases = 0

    # A Composer tag carries a leading v; the graph stores the bare version. Keying on
    # the raw tag reported the same advisory twice, and the unmatched one was banded as
    # though the package were installed and reachable.
    for reported in ("v12.67.0", "12.67.0", "V12.67.0"):
        node = index.package_node("composer", "laravel/framework", reported)
        assert node is not None and node["version"] == "12.67.0", reported
        cases += 1
    assert index.package_node("composer", "laravel/framework", "12.68.0") is None
    cases += 1

    # PyPI names are case- and separator-insensitive.
    assert index.package_node("pip", "Requests", "2.25.1") is not None
    cases += 1

    # osv-scanner resolves transitive packages the manifest never names. They have no
    # node, so they belong to the project that owns the file, never to the file: that
    # path is not a project, and counting it reported more projects than exist.
    rows = osv_projects([], index.project_at("/p"), {}, "/p/requirements.txt",
                        "pip", "certifi", "2026.7.22", None, "P2", False)
    assert [r["path"] for r in rows] == ["/p"], rows
    assert rows[0]["direct"] is False
    cases += 2

    # With no project of its own, the directory still stands in for the manifest.
    rows = osv_projects([], None, {}, "/elsewhere/requirements.txt",
                        "pip", "certifi", "2026.7.22", None, "P2", False)
    assert [r["path"] for r in rows] == ["/elsewhere"], rows
    cases += 1

    # A package the graph knows keeps its real consumers.
    node = index.package_node("composer", "laravel/framework", "v12.67.0")
    rows = osv_projects(index.consumers(node["id"]), None, {}, "/p/composer.lock",
                        "composer", "laravel/framework", "12.67.0", "12.68.0", "P1", False)
    assert [r["path"] for r in rows] == ["/p"] and rows[0]["direct"] is True, rows
    cases += 1

    print(f"match selftest ok: {cases} osv-attribution cases")


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
        return selftest_match()
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
    runtimes = match_runtimes(index, intel, kev_by_cve)
    project_runtimes = match_project_runtimes(index, intel, graph)

    previous = set()
    if args.state and Path(args.state).is_file():
        try:
            old = json.loads(Path(args.state).read_text(encoding="utf-8"))
            previous = {f["key"] for f in old.get("findings", [])
                        + old.get("leads", []) + old.get("runtimes", [])}
        except (OSError, ValueError):
            previous = set()
    for item in findings + leads + runtimes:
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
        # The scope this result was produced with, so the app can tell when the settings
        # have moved on since and the numbers on screen describe a different machine.
        "scope": {"roots": graph.get("roots") or [], "ignored": graph.get("ignored") or []},
        "counts": counts,
        "advisories_considered": len(intel.get("advisories", [])),
        "had_previous_state": bool(previous),
        "findings": findings,
        "leads": leads,
        "runtimes": runtimes,
        "project_runtimes": project_runtimes,
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
