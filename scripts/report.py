#!/usr/bin/env python3
"""Turn findings into a ranked action list, a project-wise dependency graph, and Mermaid source."""

import argparse
import html
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vercmp import highest  # noqa: E402

BANDS = [
    ("P0", "Act now", "Exploited in the wild, or critical and reachable at runtime."),
    ("P1", "Patch this week", "High impact on code you actually run."),
    ("P2", "Schedule", "Real but contained — dev-only, CI-only, or a dormant project."),
    ("P3", "Monitor", "Low exposure. No action unless the context changes."),
]
ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
MAX_INSTANCES = 2600
D3_URL = "https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"
D3_CACHE = Path.home() / ".claude" / "vuln-radar" / "vendor" / "d3.v7.8.5.min.js"


def d3_script():
    """Inline d3 so the page works offline, in a WKWebView, and when shared.

    A file:// page is not allowed to pull a remote script, so a CDN tag leaves the graph
    blank everywhere except behind a web server. Cached after the first fetch.
    """
    if D3_CACHE.is_file() and D3_CACHE.stat().st_size > 100_000:
        return "<script>" + D3_CACHE.read_text(encoding="utf-8") + "</script>"
    try:
        with urllib.request.urlopen(D3_URL, timeout=30) as resp:
            source = resp.read().decode("utf-8")
        D3_CACHE.parent.mkdir(parents=True, exist_ok=True)
        D3_CACHE.write_text(source, encoding="utf-8")
        return "<script>" + source + "</script>"
    except (urllib.error.URLError, OSError, ValueError):
        return '<script src="' + D3_URL + '"></script>'


def short(path, home):
    path = str(path)
    return "~" + path[len(home):] if home and path.startswith(home) else path


def worst(bands):
    return min(bands, key=lambda b: ORDER[b]) if bands else "P3"


def group_findings(findings):
    """One row per package version: the thing you actually upgrade."""
    groups = defaultdict(lambda: {"advisories": [], "projects": {}})
    for finding in findings:
        key = (finding["ecosystem"], finding["package"], finding["installed"])
        group = groups[key]
        group["ecosystem"], group["package"] = finding["ecosystem"], finding["package"]
        group["installed"] = finding["installed"]
        group["advisories"].append(finding)
        for project in finding["projects"]:
            existing = group["projects"].get(project["path"])
            if existing is None or (project["direct"] and not existing["direct"]):
                group["projects"][project["path"]] = project
    rows = []
    for group in groups.values():
        advisories = group["advisories"]
        band = worst([a["band"] for a in advisories])
        fixes = [a.get("fixed_version") for a in advisories if a.get("fixed_version")]
        rows.append({
            "band": band,
            "ecosystem": group["ecosystem"],
            "package": group["package"],
            "installed": group["installed"],
            "target": highest(fixes),
            "advisories": sorted(advisories, key=lambda a: (ORDER[a["band"]],
                                                            -(a.get("cvss") or 0))),
            "projects": sorted(group["projects"].values(), key=lambda p: p["path"]),
            "kev": any(a.get("kev") for a in advisories),
            "malware": any(a.get("malware") for a in advisories),
            "new": any(a.get("new") for a in advisories),
            "worst_cvss": max((a.get("cvss") or 0) for a in advisories),
            "reach": advisories[0].get("reach", {}),
            "confident": all(a.get("confident", True) for a in advisories),
            # False only when every advisory for this package is out of Dependabot's
            # reach: no GHSA id, no published fix, or a malicious-package advisory.
            "dependabot_reachable": any(a.get("dependabot_reachable", True)
                                        for a in advisories),
            "via_window": any(a.get("source") != "osv-scanner" for a in advisories),
            "via_osv": any(a.get("source") == "osv-scanner" for a in advisories),
        })
    rows.sort(key=lambda r: (ORDER[r["band"]], -r["worst_cvss"], r["package"]))
    return rows


def project_nodes(graph):
    return {n["path"]: n for n in graph.get("nodes", []) if n.get("kind") == "project"}


def coverage(node):
    """Would anything else have told the user about this?

    Dependabot draws on the same GitHub Advisory Database, so for a GitHub repo with
    alerts on it is largely duplicate. The point of saying so is to direct attention
    at the projects nothing else is watching.
    """
    if not node:
        return ("unknown", "Project metadata unavailable.")
    slug = node.get("github")
    config = node.get("dependabot") or {}
    if not slug:
        if not node.get("git_remote"):
            return ("alone", "Not a git repo — nothing else is watching this.")
        return ("alone", "Remote is not GitHub — Dependabot does not apply here.")
    if not config.get("present"):
        return ("partial",
                f"On GitHub ({slug}) with no dependabot.yml. Dependabot alerts may still "
                "be on at the repo or org level; its PRs are not configured here.")
    if config.get("version_updates_disabled"):
        return ("partial",
                f"On GitHub ({slug}). dependabot.yml sets open-pull-requests-limit: 0, so "
                "it raises no version-update PRs. Security updates depend on the repo's "
                "Dependabot alerts setting, which this scan cannot read.")
    ignored = config.get("ignored_outright") or []
    note = f"On GitHub ({slug}) with Dependabot configured — it likely reports these too."
    if ignored:
        note += (" Ignored outright (which also suppresses security PRs): "
                 + ", ".join(f"`{i}`" for i in ignored[:5]) + ".")
    return ("covered", note)


def by_project(rows):
    """Flip the package-centric rows into the per-repo view: what do I fix in here?"""
    projects = {}
    for row in rows:
        for project in row["projects"]:
            entry = projects.setdefault(project["path"], {
                "path": project["path"], "name": project["name"],
                "stale_days": project.get("stale_days"), "items": [],
            })
            # The row's band is the worst case across every project it touches; prefer the
            # one computed for this project, so a checkout with nothing installed is not
            # ranked by someone else's exposure.
            entry["items"].append({**row, "rel": project["rel"],
                                   "band": project.get("band") or row["band"],
                                   "direct": project["direct"], "fix": project["fix"],
                                   "pinned_only": (project.get("deps_installed") or {})
                                   .get("known") is True
                                   and not (project.get("deps_installed") or {})
                                   .get("present")})
    out = []
    for entry in projects.values():
        entry["items"].sort(key=lambda i: (ORDER[i["band"]], -i["worst_cvss"], i["package"]))
        entry["band"] = worst([i["band"] for i in entry["items"]])
        entry["counts"] = {b: sum(1 for i in entry["items"] if i["band"] == b) for b in ORDER}
        entry["kev"] = any(i["kev"] for i in entry["items"])
        entry["new"] = sum(1 for i in entry["items"] if i["new"])
        out.append(entry)
    out.sort(key=lambda e: (ORDER[e["band"]], -len(e["items"]), e["path"]))
    return out


def project_fix_block(entry, home, limit=12):
    """Everything to run inside one repo, in one place."""
    lines = [f"cd {short(entry['path'], home)}"]
    seen = set()
    for item in entry["items"][:limit]:
        if item["fix"] not in seen:
            seen.add(item["fix"])
            lines.append(item["fix"])
    if len(entry["items"]) > limit:
        lines.append(f"# ...and {len(entry['items']) - limit} lower-priority package(s)")
    return lines


def render_markdown(data, rows, projects, home, nodes):
    intel = data.get("intel", {})
    stats = data.get("graph_stats", {})
    counts = data.get("counts", {})
    leads = data.get("leads", [])
    out = []
    w = out.append

    total = sum(counts.values())
    w("# Vulnerability radar")
    w("")
    w(f"- **Scanned** {stats.get('projects', 0)} projects / "
      f"{stats.get('packages', 0)} resolved packages "
      f"({stats.get('nodes', 0)} graph nodes, {stats.get('edges', 0)} edges)")
    w(f"- **Advisory window** {intel.get('window_days')} days "
      f"(published since {intel.get('published_since')}) — "
      f"{data.get('advisories_considered', 0)} advisories across "
      f"{', '.join(intel.get('ecosystems') or [])}")
    w(f"- **KEV catalog** {intel.get('kev_catalog')} (CISA known-exploited)")
    w(f"- **Result** {total} findings in {len(projects)} project(s) — "
      + ", ".join(f"{band} {counts.get(band, 0)}" for band, _, _ in BANDS))
    recent = sum(1 for f in data.get("findings", []) if f.get("source") != "osv-scanner")
    backlog = total - recent
    w(f"- **Recent vs backlog** {recent} disclosed in the window, {backlog} older "
      "advisories found by osv-scanner")
    if data.get("had_previous_state"):
        w(f"- **New since last run** {sum(1 for r in rows if r['new'])} package(s)")
    for err in intel.get("errors") or []:
        w(f"- ⚠️ feed warning: {err}")
    w("")

    malware = data.get("malware") or []
    alerts = data.get("alerts") or []
    installs = data.get("install_scripts") or {}
    w("## Malicious code check")
    w("")
    if malware:
        unpacked_any = any(m.get("installed_on_disk") for m in malware)
        w(f"### ⚠️ {len(malware)} known-malicious package"
          + ("s" if len(malware) != 1 else "")
          + (" unpacked on disk" if unpacked_any else " pinned in a lockfile"))
        w("")
        w("A `MAL-*` advisory means the ecosystem has marked this package version "
          "itself as malicious.")
        w("")
        for item in malware[:20]:
            unpacked = item.get("installed_on_disk")
            dormant = item.get("dormant_days")
            state = ("**unpacked in node_modules**" if unpacked
                     else "declared in the lockfile, not installed")
            age = (f", last commit {dormant}d ago" if dormant and dormant > 365 else "")
            w(f"- `{item['package']}@{item['installed']}` — {item.get('advisory')} "
              f"({state}{age})")
            for project in item["projects"][:3]:
                w(f"  - `{short(project['path'], home)}` "
                  f"({'direct' if project.get('direct') else 'transitive'})")
        w("")
        if any(m.get("installed_on_disk") for m in malware):
            w("At least one is unpacked on disk. Treat that as a compromise: quarantine "
              "the project, do not install or build, and rotate any credential "
              "reachable from it.")
        else:
            w("None are unpacked on disk — they are pinned in lockfiles that nothing has "
              "installed. The risk is realised only if someone runs an install there, so "
              "bump or remove the pin before anyone does.")
        w("")
    if alerts:
        w(f"### ⚠️ {len(alerts)} suspicious install hook(s)")
        w("")
        w("Lifecycle scripts run automatically on `npm install`. These matched patterns "
          "associated with supply-chain payloads — read each one before installing.")
        w("")
        for alert in alerts[:20]:
            w(f"- `{short(alert['project'], home)}` — **{alert['hook']}** "
              f"{alert['why']}")
            w(f"  ```")
            w(f"  {alert['command']}")
            w(f"  ```")
        w("")
    if not malware and not alerts:
        w("No known-malicious packages (`MAL-*`) and no suspicious lifecycle scripts in "
          "your own manifests.")
        w("")

    exposure = data.get("install_exposure") or {}
    blocked, running = exposure.get("blocked") or [], exposure.get("running") or []
    if blocked or running:
        w("### Install-time execution")
        w("")
        w("Install scripts are where supply-chain payloads fire, so what matters is "
          "whether a dependency can run code here at all.")
        w("")
        if blocked:
            reasons = {}
            for row in blocked:
                reasons.setdefault(row["why"], []).append(row["name"])
            w(f"**{len(blocked)} project(s) block it:**")
            w("")
            for why, names in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
                w(f"- {len(names)} × {why}")
            w("")
        if running:
            exposed = [r for r in running if r["packages"]]
            w(f"**{len(running)} project(s) allow it**"
              + (f", {len(exposed)} with dependencies that actually have install scripts:"
                 if exposed else ", none of which have dependencies with install scripts."))
            w("")
            for row in exposed[:12]:
                w(f"- `{row['name']}` ({row['manager']}) — "
                  + ", ".join(f"`{p}`" for p in row["packages"][:5])
                  + (" …" if len(row["packages"]) > 5 else ""))
            w("")

    if not rows and not leads:
        w("## No action needed")
        w("")
        w("Nothing in the advisory window matches a version installed on this machine.")
        return "\n".join(out) + "\n"

    act = [p for p in projects if p["band"] in ("P0", "P1")]
    if act:
        w("## Projects needing action")
        w("")
        w("| | Project | P0 | P1 | P2 | P3 | Last commit |")
        w("|---|---|---|---|---|---|---|")
        for entry in act:
            flag = "🔴" if entry["band"] == "P0" else "🟠"
            stale = entry.get("stale_days")
            age = f"{stale}d ago" if stale is not None else "—"
            counts_p = entry["counts"]
            w(f"| {flag} | `{short(entry['path'], home)}` | {counts_p['P0'] or ''} | "
              f"{counts_p['P1'] or ''} | {counts_p['P2'] or ''} | {counts_p['P3'] or ''} | "
              f"{age} |")
        w("")

    buckets = {"alone": [], "partial": [], "covered": [], "unknown": []}
    for entry in projects:
        buckets[coverage(nodes.get(entry["path"]))[0]].append(entry)
    w("## Dependabot")
    w("")
    w("These come from the GitHub Advisory Database, the same source Dependabot uses. "
      "A ✓ in the Dependabot column means that project's repo is on GitHub, so "
      "Dependabot will flag and raise it too if you have it turned on there. Nothing "
      "is hidden on that basis.")
    w("")

    unreachable = [r for r in rows if not r.get("dependabot_reachable", True)]
    if unreachable:
        w("### Dependabot cannot raise these")
        w("")
        w("Out of its reach whatever your repo settings — no GHSA id to alert on, no "
          "published fix to bump to, or a malicious-package advisory. These are yours "
          "to handle.")
        w("")
        w("| Package | Installed | Why |")
        w("|---|---|---|")
        for row in unreachable[:30]:
            if row.get("malware"):
                why = "**malicious package** — quarantine, do not upgrade"
            elif not row["target"]:
                why = "no published fix — mitigate, pin, or drop the dependency"
            else:
                why = "advisory has no GHSA id, so it never reaches Dependabot"
            w(f"| `{row['package']}` | `{row['installed']}` | {why} |")
        if len(unreachable) > 30:
            w(f"| … | | {len(unreachable) - 30} more |")
        w("")

    w("## By project")
    w("")
    for entry in projects:
        if entry["band"] in ("P2", "P3"):
            continue
        flags = []
        if entry["kev"]:
            flags.append("**exploited in the wild**")
        if entry["new"]:
            flags.append(f"{entry['new']} new since last run")
        stale = entry.get("stale_days")
        if stale is not None and stale > 120:
            flags.append(f"dormant — last commit {stale}d ago")
        w(f"### {short(entry['path'], home)}")
        w("")
        w(f"`{entry['band']}` · {len(entry['items'])} affected package(s)"
          + (" · " + " · ".join(flags) if flags else ""))
        w("")

        covered = bool((nodes.get(entry["path"]) or {}).get("github"))
        w("_Dependabot raises these only for repos on GitHub, and only if it is "
          "switched on for that repo._")
        w("")
        w("| | Package | Installed | Upgrade to | How it is pulled in | Age | "
          "Dependabot | Advisories |")
        w("|---|---|---|---|---|---|---|---|")
        for item in entry["items"]:
            mark = {"P0": "🔴", "P1": "🟠", "P2": "🟡", "P3": "⚪"}[item["band"]]
            how = ("direct" if item["direct"] else "transitive")
            if item["rel"] == "dev":
                how += ", dev"
            elif item["rel"] == "ci_uses":
                how += ", CI"
            ids = ", ".join(f"[{a['advisory']}]({a['url']})" if a.get("url")
                            else str(a.get("advisory") or a.get("cve"))
                            for a in item["advisories"][:2])
            if len(item["advisories"]) > 2:
                ids += f" +{len(item['advisories']) - 2}"
            origin = ("recent" if item["via_window"] and not item["via_osv"]
                      else "backlog" if item["via_osv"] and not item["via_window"]
                      else "both")
            w(f"| {mark} | `{item['package']}` | `{item['installed']}` | "
              f"`{item['target'] or '—'}` | {how} | {origin} | "
              f"{'✓' if covered else '✗'} | {ids} |")
        w("")
        w("```bash")
        for line in project_fix_block(entry, home):
            w(line)
        w("```")
        w("")

    quiet = [p for p in projects if p["band"] in ("P2", "P3")]
    if quiet:
        w(f"### Lower priority ({len(quiet)} projects)")
        w("")
        w("| Project | Worst | Packages | Last commit |")
        w("|---|---|---|---|")
        for entry in quiet:
            stale = entry.get("stale_days")
            w(f"| `{short(entry['path'], home)}` | {entry['band']} | "
              f"{len(entry['items'])} | {f'{stale}d ago' if stale is not None else '—'} |")
        w("")

    w("## Advisory detail")
    w("")
    for band, title, blurb in BANDS:
        band_rows = [r for r in rows if r["band"] == band]
        if not band_rows:
            continue
        w(f"### {band} — {title} ({len(band_rows)} package(s))")
        w("")
        w(f"_{blurb}_")
        w("")
        if band in ("P0", "P1"):
            for row in band_rows:
                flags = []
                if row["kev"]:
                    flags.append("**exploited in the wild (CISA KEV)**")
                if row["malware"]:
                    flags.append("**known-malicious package**")
                if row["new"]:
                    flags.append("new since last run")
                if not row["confident"]:
                    flags.append("version inferred from a declared range — confirm with a lockfile")
                w(f"**`{row['package']}` {row['installed']} → "
                  f"{row['target'] or 'no published fix'}** ({row['ecosystem']}, "
                  f"{len(row['projects'])} project(s))")
                w("")
                if flags:
                    w("> " + " · ".join(flags))
                    w("")
                for adv in row["advisories"]:
                    bits = [adv["severity"]]
                    if adv.get("cvss"):
                        bits.append(f"CVSS {adv['cvss']}")
                    if adv.get("epss"):
                        bits.append(f"EPSS {adv['epss'] * 100:.1f}%")
                    if adv.get("cve"):
                        bits.append(adv["cve"])
                    link = (f"[{adv['advisory']}]({adv['url']})" if adv.get("url")
                            else adv["advisory"])
                    w(f"- {link} ({', '.join(str(b) for b in bits)}) — {adv.get('summary') or ''}")
                    w(f"  - vulnerable: `{adv['vulnerable_range']}`")
                    if adv.get("kev_due"):
                        w(f"  - CISA remediation due {adv['kev_due']}"
                          + (" · linked to ransomware campaigns"
                             if adv.get("ransomware") else ""))
                if not row["target"]:
                    w("- No fixed version published yet — mitigate or pin, and track it.")
                w("")
            continue
        w("| Package | Installed | Upgrade to | Advisories | Projects | Exposure |")
        w("|---|---|---|---|---|---|")
        for row in band_rows:
            ids = ", ".join(str(a["advisory"] or a.get("cve") or "?")
                            for a in row["advisories"][:3])
            if len(row["advisories"]) > 3:
                ids += f" +{len(row['advisories']) - 3}"
            reach = row["reach"]
            exposure = ("runtime" if reach.get("runtime") else
                        "CI only" if reach.get("ci_only") else "dev only")
            if not reach.get("active"):
                exposure += ", dormant"
            w(f"| `{row['package']}` | `{row['installed']}` | `{row['target'] or '—'}` | "
              f"{ids} | {len(row['projects'])} | {exposure} |")
        w("")

    runtimes = data.get("runtimes") or []
    if runtimes:
        running = [r for r in runtimes if r.get("running")]
        pinned = [r for r in runtimes if not r.get("running")]
        w(f"## Runtime ({len(runtimes)})")
        w("")
        w("Core advisories for the interpreter itself. These carry no package ecosystem, "
          "so they never appear in the dependency findings above — upgrading a package "
          "will not clear them.")
        w("")
        for group, label in ((running, "Installed and running"),
                             (pinned, "Pinned by a checkout, not the version running")):
            if not group:
                continue
            version = group[0]["installed"]
            target = max((r.get("fixed_version") or "" for r in group), default="")
            w(f"**{label}: `{group[0]['package']} {version}`** "
              f"— {len(group)} advisor{'y' if len(group) == 1 else 'ies'}"
              + (f", fixed in `{target}`" if target else ""))
            w("")
            w("| CVE | Severity | Fixed in | Summary |")
            w("|---|---|---|---|")
            for item in group[:25]:
                cve = item.get("cve") or item["advisory"]
                link = f"[{cve}]({item['url']})" if item.get("url") else f"`{cve}`"
                w(f"| {link} | {item['severity']} | `{item.get('fixed_version') or '—'}` | "
                  f"{(item.get('summary') or '').splitlines()[0][:90]} |")
            w("")
            if group[0].get("fix"):
                w(f"```\n{group[0]['fix']}\n```")
                w("")

    projects_on_node = data.get("project_runtimes") or []
    if projects_on_node:
        affected = [r for r in projects_on_node if r.get("advisories")]
        w(f"### Projects running on a vulnerable node ({len(affected)})")
        w("")
        w("Only projects node actually runs: a Lambda, a server, a command. A front end "
          "declares `engines.node` for its build toolchain, and a core CVE in that "
          "interpreter never reaches what it ships, so those are left out.")
        w("")
        if affected:
            w("| Project | Runs on | Declares | Advisories | Fixed in |")
            w("|---|---|---|---|---|")
            for item in affected:
                w(f"| `{item['name']}` | `{item['resolved']}` | "
                  f"`{item['requires']}` ({item['requires_from']}) | "
                  f"{len(item['advisories'])} | `{item.get('fixed_version') or '—'}` |")
            w("")
        unresolved = [r for r in projects_on_node if not r.get("resolved")]
        for item in unresolved:
            w(f"- `{item['name']}` asks for `{item['requires']}` and no node installed "
              "here satisfies it, so nothing could be checked.")
        if unresolved:
            w("")

    if leads:
        w(f"## Host-layer leads ({len(leads)})")
        w("")
        w("Known-exploited CVEs naming software installed on this machine. KEV publishes no "
          "machine-readable version ranges, so these are **leads, not confirmed findings** — "
          "check each advisory against your installed version before acting.")
        w("")
        w("| CVE | Vendor / product | Added | Installed here |")
        w("|---|---|---|---|")
        for lead in leads[:40]:
            matches = ", ".join(f"`{m['name']} {m.get('version') or ''}`".strip()
                                for m in lead["matches"][:4])
            w(f"| [{lead['cve']}]({lead['url']}) | {lead.get('vendor')} / "
              f"{lead.get('product')} | {lead.get('added')} | {matches} |")
        w("")

    blast = [r for r in sorted(rows, key=lambda r: -len(r["projects"]))[:8]
             if len(r["projects"]) > 1]
    if blast:
        w("## Blast radius")
        w("")
        w("Shared packages — one upgrade clears several projects:")
        w("")
        for row in blast:
            w(f"- `{row['package']}` {row['installed']} → {len(row['projects'])} projects "
              f"({row['band']})")
        w("")

    skipped = (data.get("graph_stats") or {}).get("skipped_binary_lockfiles") or []
    if skipped:
        w("## Coverage gaps")
        w("")
        for path in skipped[:10]:
            w(f"- `{short(path, home)}` is a binary lockfile; run "
              f"`bun install --save-text-lockfile` to make it scannable")
        w("")
    return "\n".join(out) + "\n"


def build_render_graph(graph, rows, leads, home):
    """Project-wise: every project is its own cluster holding the packages it pulls in.

    A package used by several projects appears once per project, so each cluster reads as
    "what is in this repo". The shared count rides along on the node for the tooltip.
    """
    nodes = {n["id"]: n for n in graph["nodes"]}
    band_of, row_of = {}, {}
    for row in rows:
        key = f"pkg:{row['ecosystem']}:{row['package']}@{row['installed']}"
        band_of[key] = row["band"]
        row_of[key] = row

    degree = defaultdict(int)
    for edge in graph["edges"]:
        if nodes.get(edge["source"], {}).get("kind") == "project":
            degree[edge["target"]] += 1

    affected = set(band_of)
    direct = {e["target"] for e in graph["edges"] if e.get("direct")}

    pairs = []
    for edge in graph["edges"]:
        project = nodes.get(edge["source"])
        package = nodes.get(edge["target"])
        if not project or not package or project["kind"] != "project":
            continue
        if package["kind"] not in ("package", "image", "runtime"):
            continue
        tier = 0 if package["id"] in affected else (1 if package["id"] in direct else 2)
        pairs.append((tier, project, package, edge))
    pairs.sort(key=lambda p: (p[0], -degree[p[2]["id"]]))
    # Affected packages are the point of the graph, so they are never cut; the cap only
    # trims the clean context around them.
    required = [p for p in pairs if p[0] == 0]
    extra = [p for p in pairs if p[0] != 0]
    pairs = required + extra[:max(0, MAX_INSTANCES - len(required))]

    used_projects = {}
    out_nodes, out_edges = [], []
    seen_instances = set()
    for tier, project, package, edge in pairs:
        pid = project["id"]
        instance = f"{pid}||{package['id']}"
        # One project can reach the same package down more than one edge — a runtime
        # dependency that is also used by a workflow, or a package named in both the
        # manifest and the lockfile. Those are one node, and emitting it twice gives d3
        # a duplicate key, which breaks the join and leaves the canvas empty. The sort
        # above puts the affected edge first, so the first one wins.
        if instance in seen_instances:
            continue
        seen_instances.add(instance)
        if pid not in used_projects:
            used_projects[pid] = project
        node = {
            "id": instance, "cluster": pid, "kind": package["kind"],
            "name": package["name"], "version": package.get("version"),
            "ecosystem": package.get("ecosystem"), "band": band_of.get(package["id"]),
            "shared": degree.get(package["id"], 1), "rel": edge["rel"],
            "direct": bool(edge.get("direct")),
        }
        row = row_of.get(package["id"])
        if row:
            node["target"] = row["target"]
            node["kev"] = row["kev"]
            node["projects"] = len(row["projects"])
            node["fix"] = next((p["fix"] for p in row["projects"]
                                if p["path"] == project.get("path")), None)
            # Trimmed: the drawer shows a summary, not an essay, and this payload is
            # parsed on every graph load.
            node["adv"] = [{
                "id": a.get("advisory"), "cve": a.get("cve"),
                "sev": a.get("severity"), "cvss": a.get("cvss"),
                "epss": a.get("epss"),
                "sum": (a.get("summary") or "")[:180],
                "url": a.get("url"), "kev": bool(a.get("kev")),
                "range": a.get("vulnerable_range"),
            } for a in row["advisories"][:12]]
        out_nodes.append(node)
        out_edges.append({"source": pid, "target": instance, "rel": edge["rel"]})

    lead_nodes = {m["id"]: m for lead in leads for m in lead["matches"]}
    if lead_nodes:
        used_projects["host"] = {"id": "host", "name": "host / runtime", "path": "",
                                 "stale_days": None}
        for nid, match in lead_nodes.items():
            out_nodes.append({
                "id": f"host||{nid}", "cluster": "host", "kind": match["kind"],
                "name": match["name"], "version": match.get("version"),
                "ecosystem": "host", "band": None, "lead": True, "shared": 1,
                "rel": "installed", "direct": True,
            })
            out_edges.append({"source": "host", "target": f"host||{nid}", "rel": "installed"})

    clusters = []
    for pid, project in used_projects.items():
        members = [n for n in out_nodes if n["cluster"] == pid]
        bands = [n["band"] for n in members if n["band"]]
        clusters.append({
            "id": pid,
            "name": project.get("name") or pid,
            "path": short(project.get("path") or "", home),
            "band": worst(bands) if bands else None,
            "affected": len(bands),
            "total": len(members),
            "stale": project.get("stale_days"),
            "github": project.get("github"),
        })
    clusters.sort(key=lambda c: (ORDER.get(c["band"], 9), -c["affected"], c["name"]))
    for cluster in clusters:
        out_nodes.append({"id": cluster["id"], "cluster": cluster["id"], "kind": "project",
                          "name": cluster["name"], "path": cluster["path"],
                          "band": cluster["band"], "shared": cluster["total"],
                          "affected": cluster["affected"], "stale": cluster["stale"]})
    hidden = max(0, sum(1 for n in graph["nodes"] if n["kind"] == "package") - len(affected))
    return out_nodes, out_edges, clusters, hidden


def render_mermaid(rows, home):
    lines = ["graph LR",
             "  classDef p0 fill:#fdecea,stroke:#b3261e,stroke-width:2px;",
             "  classDef p1 fill:#fdf0e3,stroke:#c4610a,stroke-width:2px;",
             "  classDef p2 fill:#fcf8e3,stroke:#8a6d00;",
             "  classDef p3 fill:#eef2f4,stroke:#4a6572;"]
    ids = {}

    def mid(prefix, key):
        if key not in ids:
            ids[key] = f"{prefix}{len(ids)}"
        return ids[key]

    bands = defaultdict(list)
    projects = by_project([r for r in rows if r["band"] in ("P0", "P1")])
    for entry in projects[:14]:
        pid = mid("p", entry["path"])
        lines.append(f'  subgraph {pid}["{Path(entry["path"]).name}"]')
        for item in entry["items"][:8]:
            node = mid("v", f"{entry['path']}|{item['package']}@{item['installed']}")
            label = f"{item['package']}<br/>{item['installed']} → {item['target'] or '?'}"
            lines.append(f'    {node}["{label}"]')
            bands[item["band"].lower()].append(node)
        lines.append("  end")
    for cls, members in bands.items():
        if members:
            lines.append(f"  class {','.join(sorted(set(members)))} {cls};")
    return "\n".join(lines) + "\n"


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
__D3__
<style>
  :root {
    --bg: #fbfaf8; --panel: #ffffff; --ink: #1b1b1a; --muted: #6b6b68;
    --line: #e3e1dd; --p0: #b3261e; --p1: #c4610a; --p2: #b08900; --p3: #7a8b94;
    --proj: #2b5cb8; --clean: #c3c1bc;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #1B1D23; --panel: #23262E; --ink: #F6F7FA; --muted: #8B92A2;
      --line: #2A2E36; --p0: #E2555F; --p1: #E0883C; --p2: #A89446; --p3: #6E7D8F;
      --proj: #7C82F0; --clean: #474C57;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 14px/1.5 ui-sans-serif, -apple-system, "Segoe UI", sans-serif; }
  header { padding: 16px 20px 10px; border-bottom: 1px solid var(--line); }
  h1 { margin: 0 0 3px; font-size: 17px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 12.5px; }
  .wrap { display: flex; height: calc(100vh - 118px); }
  @media (max-width: 900px) { .wrap { flex-direction: column; height: auto; } }
  #canvas { flex: 1; min-height: 460px; position: relative; overflow: hidden; }
  aside { width: 300px; border-right: 1px solid var(--line); background: var(--panel);
    overflow-y: auto; padding: 12px; }
  @media (max-width: 900px) { aside:not(.drawer) { width: auto; border-right: 0;
    border-bottom: 1px solid var(--line); max-height: 260px; } }
  .ptitle { font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
    color: var(--muted); margin: 6px 4px 8px; }
  .proj { display: flex; align-items: center; gap: 8px; padding: 6px 8px;
    border-radius: 8px; cursor: pointer; font-size: 13px; }
  .proj:hover { background: color-mix(in srgb, var(--ink) 7%, transparent); }
  .proj[aria-selected="true"] { background: color-mix(in srgb, var(--proj) 18%, transparent); }
  .proj .nm { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .proj .ct { color: var(--muted); font-size: 11.5px; font-variant-numeric: tabular-nums; }
  .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
  .controls { display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
    padding: 9px 20px; border-bottom: 1px solid var(--line); }
  button { font: inherit; font-size: 12.5px; padding: 4px 10px; border-radius: 999px;
    border: 1px solid var(--line); background: var(--panel); color: var(--ink);
    cursor: pointer; }
  button[aria-pressed="true"] { border-color: var(--proj); color: var(--proj); }
  .tip { position: absolute; pointer-events: none; background: var(--panel);
    border: 1px solid var(--line); border-radius: 8px; padding: 7px 10px; font-size: 12.5px;
    box-shadow: 0 6px 20px rgba(0,0,0,.16); max-width: 270px; opacity: 0; z-index: 5; }
  .tip b { display: block; }
  .tip span { color: var(--muted); }
  .lbl { font-size: 11px; fill: var(--muted); pointer-events: none;
    text-anchor: middle; font-weight: 600; }
  .lbl.hot { fill: var(--ink); }
  svg { display: block; }
  .link { stroke: var(--line); }
  .legend { display: flex; gap: 12px; flex-wrap: wrap; padding: 7px 20px;
    border-top: 1px solid var(--line); font-size: 12px; color: var(--muted);
    align-items: center; }
  .legend i { margin-right: 4px; }
  .drawer { display: none; flex: 0 0 340px; width: 340px; position: relative;
    align-self: stretch; height: 100%; box-sizing: border-box;
    background: var(--panel); border-left: 1px solid var(--line); overflow-y: auto;
    padding: 16px 18px 24px; }
  .drawer.open { display: block; }
  @media (max-width: 620px) { .drawer { flex-basis: 100%; width: 100%; } }
  .drawer h2 { margin: 0 0 2px; font-size: 16px; letter-spacing: -0.01em; }
  .drawer .close { position: absolute; top: 12px; right: 14px; border: 0; background: none;
    color: var(--muted); font-size: 17px; cursor: pointer; padding: 2px 6px; }
  .drawer .close:hover { color: var(--ink); }
  .jump { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px;
    margin: 6px 0 10px; }
  .jump .to { color: #4ade80; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
  .chip { font-size: 11px; padding: 2px 7px; border-radius: 999px; border: 1px solid var(--line);
    color: var(--muted); }
  .chip.dep { color: var(--proj);
    border-color: color-mix(in srgb, var(--proj) 45%, transparent);
    background: color-mix(in srgb, var(--proj) 13%, transparent); }
  .chip.nodep { color: var(--p1);
    border-color: color-mix(in srgb, var(--p1) 45%, transparent);
    background: color-mix(in srgb, var(--p1) 13%, transparent); }
  .chip.kev { color: var(--p0); border-color: color-mix(in srgb, var(--p0) 45%, transparent);
    background: color-mix(in srgb, var(--p0) 13%, transparent); font-weight: 600; }
  .adv { border-top: 1px solid var(--line); padding: 11px 0; }
  .adv a { color: var(--proj); text-decoration: none;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .adv a:hover { text-decoration: underline; }
  .adv .meta { display: flex; gap: 7px; align-items: center; flex-wrap: wrap;
    margin-bottom: 4px; }
  .adv .sev { font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .04em; }
  .adv .sum { font-size: 12.5px; color: var(--ink); opacity: .86; line-height: 1.45; }
  .adv .rng { font-size: 11px; color: var(--muted);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-top: 4px; }
  .fix { margin-top: 14px; border-top: 1px solid var(--line); padding-top: 12px; }
  .fix code { display: block; background: var(--bg); border: 1px solid var(--line);
    border-radius: 7px; padding: 9px 11px; font-size: 11.5px; white-space: pre-wrap;
    word-break: break-all; }
  .fix button { margin-top: 8px; }
  .hint { font-size: 11.5px; color: var(--muted); margin-top: 10px; }

  /* Embedded in the app: it already has a title bar, a project list and a legend,
     so the page shows only the canvas and its controls. The app is dark regardless of
     the system setting, so pin the dark tokens rather than following prefers-color-scheme. */
  html[data-embed] {
    --bg: #1B1D23; --panel: #23262E; --ink: #F6F7FA; --muted: #8B92A2;
    --line: #2A2E36; --p0: #E2555F; --p1: #E0883C; --p2: #A89446; --p3: #6E7D8F;
    --proj: #7C82F0; --clean: #474C57;
  }
  html[data-embed] body { background: #1B1D23; }
  html[data-embed] header,
  html[data-embed] aside:not(.drawer),
  html[data-embed] .legend { display: none !important; }
  /* The embedded pane is narrow but it is not a phone: keep the side-by-side layout
     and a drawer that leaves the graph visible. */
  html[data-embed] .wrap { flex-direction: row; height: calc(100vh - 41px); }
  html[data-embed] .drawer {
    flex: 0 0 min(330px, 48%); width: min(330px, 48%);
    height: calc(100vh - 41px);
  }
  html[data-embed] .controls { border-top: 0; padding: 8px 14px; }
</style>
</head>
<body>
<header>
  <h1>__TITLE__</h1>
  <div class="sub">__SUBTITLE__</div>
</header>
<div class="controls">
  <button id="t-aff" aria-pressed="true">Affected only</button>
  <button id="t-all" aria-pressed="false">All dependencies</button>
  <button id="t-reset">Reset view</button>
  <span class="sub" id="shown" style="margin-left:auto"></span>
</div>
<div class="wrap">
  <aside>
    <div class="ptitle">Projects</div>
    <div id="plist"></div>
  </aside>
  <div id="canvas">
    <div class="tip" id="tip"></div>
  </div>
  <aside class="drawer" id="drawer" aria-live="polite"></aside>
</div>
<div class="legend">
  <span><i class="dot" style="background:var(--p0);display:inline-block"></i>P0</span>
  <span><i class="dot" style="background:var(--p1);display:inline-block"></i>P1</span>
  <span><i class="dot" style="background:var(--p2);display:inline-block"></i>P2</span>
  <span><i class="dot" style="background:var(--p3);display:inline-block"></i>P3</span>
  <span><i class="dot" style="background:var(--proj);display:inline-block"></i>project</span>
  <span><i class="dot" style="background:var(--clean);display:inline-block"></i>no advisory</span>
  <span>solid = runtime dependency · dashed = dev / CI</span>
</div>
<script>
const DATA = __DATA__;
const COLOR = { P0: 'var(--p0)', P1: 'var(--p1)', P2: 'var(--p2)', P3: 'var(--p3)' };
const clusterById = new Map(DATA.clusters.map(c => [c.id, c]));
let mode = 'affected', focus = null;
let frames = 0, stalled = false;

const fill = n => n.kind === 'project' ? 'var(--proj)'
  : n.band ? COLOR[n.band] : 'var(--clean)';
const radius = n => n.kind === 'project' ? 9 : n.band ? 6 : 3;

const svg = d3.select('#canvas').append('svg');
const root = svg.append('g');
const linkLayer = root.append('g').attr('stroke-opacity', .55);
const nodeLayer = root.append('g');
const labelLayer = root.append('g');
const tip = d3.select('#tip');
const zoom = d3.zoom().scaleExtent([.08, 8]).on('zoom', e => root.attr('transform', e.transform));
svg.call(zoom);

const sim = d3.forceSimulation()
  .force('link', d3.forceLink().id(d => d.id).distance(26).strength(.55))
  .force('charge', d3.forceManyBody().strength(d => d.kind === 'project' ? -140 : -24))
  .force('collide', d3.forceCollide().radius(d => radius(d) + 2.4).strength(.9))
  .force('x', d3.forceX(d => home(d).x).strength(.42))
  .force('y', d3.forceY(d => home(d).y).strength(.42));

function home(d) {
  const c = clusterById.get(d.cluster);
  return c && c.cx != null ? c : { x: 0, y: 0, cx: 0, cy: 0 };
}

function layout(active) {
  // Never more columns than there are clusters: ceil(sqrt(1 * 1.6)) is 2, which puts a
  // single focused cluster in the left column of a two-column grid — 115px off centre,
  // and a third of the pane away once the focus zoom multiplies it.
  const cols = Math.min(active.length, Math.max(1, Math.ceil(Math.sqrt(active.length * 1.6))));
  const gapX = 230, gapY = 210;
  const rows = Math.ceil(active.length / cols);
  active.forEach((c, i) => {
    c.x = c.cx = ((i % cols) - (cols - 1) / 2) * gapX;
    c.y = c.cy = (Math.floor(i / cols) - (rows - 1) / 2) * gapY;
  });
  DATA.clusters.filter(c => !active.includes(c)).forEach(c => { c.cx = null; });
}

function visibleClusters() {
  let list = DATA.clusters.filter(c => mode === 'all' || c.affected > 0);
  if (focus) list = list.filter(c => c.id === focus);
  return list;
}

function render() {
  const active = visibleClusters();
  layout(active);
  const ids = new Set(active.map(c => c.id));
  const nodes = DATA.nodes.filter(n => ids.has(n.cluster) &&
    (mode === 'all' || n.kind === 'project' || n.band));
  const keep = new Set(nodes.map(n => n.id));
  // Rebuild links by id on every render. d3 rewrites source/target into node objects,
  // and reusing those across a changed node set resolves to stale nodes, which leaves
  // the survivors with NaN positions and nothing drawn.
  const links = DATA.edges
    .map(e => ({ source: e.source.id || e.source,
                 target: e.target.id || e.target, rel: e.rel }))
    .filter(e => keep.has(e.source) && keep.has(e.target));

  document.getElementById('shown').textContent =
    active.length + ' project(s) · ' + (nodes.length - active.length) + ' package nodes' +
    (DATA.hidden && mode !== 'all' ? ' · ' + DATA.hidden + ' clean packages hidden' : '');

  const link = linkLayer.selectAll('line').data(links, d =>
    (d.source.id || d.source) + '>' + (d.target.id || d.target));
  link.exit().remove();
  link.enter().append('line').attr('class', 'link')
    .attr('stroke-width', d => d.rel === 'depends_on' ? 1 : .8)
    .attr('stroke-dasharray', d => d.rel === 'depends_on' ? null : '2,2');

  const node = nodeLayer.selectAll('circle').data(nodes, d => d.id);
  node.exit().remove();
  node.enter().append('circle')
      .attr('r', radius).attr('fill', fill)
      .attr('stroke', d => d.band ? 'rgba(0,0,0,.3)' : 'none').attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('mousemove', (event, d) => {
        const c = clusterById.get(d.cluster);
        tip.style('opacity', 1)
          .style('left', (event.offsetX + 14) + 'px')
          .style('top', (event.offsetY + 12) + 'px')
          .html('<b>' + esc(d.name) + (d.version ? ' ' + esc(d.version) : '') + '</b>' +
            '<span>' + (d.kind === 'project'
              ? esc(d.path) + ' · ' + d.affected + ' affected'
              : (d.band ? d.band + ' · ' : 'no advisory · ') +
                (d.direct ? 'direct' : 'transitive') +
                (d.rel === 'dev' ? ', dev' : d.rel === 'ci_uses' ? ', CI' : '') +
                (d.shared > 1 ? ' · in ' + d.shared + ' projects' : '') +
                ' · ' + esc(c ? c.name : '')) + '</span>');
      })
      .on('mouseleave', () => tip.style('opacity', 0))
      .on('click', (e, d) => {
        if (d.kind === 'project') { closeDrawer(); select(d.cluster === focus ? null : d.cluster); }
        else { showDetail(d); }
      })
    .merge(node).attr('fill', fill).attr('r', radius);

  const solo = active.length === 1;
  const labelled = solo ? [] : active;
  const label = labelLayer.selectAll('text').data(labelled, d => d.id);
  label.exit().remove();
  label.enter().append('text').attr('class', d => 'lbl' + (d.band === 'P0' ? ' hot' : ''))
      .text(d => d.name + (d.affected ? ' (' + d.affected + ')' : ''))
    .merge(label)
      .attr('x', d => d.cx)
      .attr('y', d => d.cy - 72 - Math.sqrt(d.total || 1) * 4);

  sim.nodes(nodes);
  sim.force('link').links(links);
  sim.on('tick', draw);
  sim.alpha(.9).restart();
  // Draw once up front rather than waiting for the first frame: a node with no cx/cy
  // sits at the origin, so without this the whole graph is a single dot until the
  // simulation runs — and it may never run, see settle().
  draw();
  if (document.hidden) {
    settle();
  } else {
    const drawn = frames;
    setTimeout(() => { if (frames === drawn) settle(); }, 500);
  }
  drawList();
}

function draw() {
  frames++;
  linkLayer.selectAll('line')
    .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  nodeLayer.selectAll('circle').attr('cx', d => d.x).attr('cy', d => d.y);
}

/// Lay the graph out without animation frames.
///
/// WebKit stops serving requestAnimationFrame to a view it considers off screen, and d3
/// drives both the force simulation and the zoom transition from it. Embedded in the app
/// the page routinely loads into a view that is not on screen yet, and then nothing fails
/// — no error, no exception — the nodes simply never receive coordinates and the pane
/// looks empty. Run the simulation to rest by hand instead and paint the result.
function settle() {
  stalled = true;
  sim.alpha(Math.max(sim.alpha(), .9));
  for (let i = 0; i < 300; i++) sim.tick();
  sim.stop();
  draw();
  fit();
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

const SEV_COLOR = { critical: 'var(--p0)', high: 'var(--p1)', medium: 'var(--p2)' };
const drawer = document.getElementById('drawer');

function closeDrawer() {
  drawer.classList.remove('open');
  relayout();
}

/// Docking the drawer resizes the canvas, so the viewBox and zoom must follow it.
function relayout() {
  // Two frames: the first lets the flex layout settle after the drawer docks or
  // undocks, the second measures the canvas at its final size.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    resize();
    render();
    fit();
  }));
}

function showDetail(d) {
  const cluster = clusterById.get(d.cluster);
  const advisories = d.adv || [];
  const chips = [];
  if (d.band) chips.push('<span class="chip" style="color:' + COLOR[d.band] +
    '">' + d.band + '</span>');
  if (d.kev) chips.push('<span class="chip kev">exploited in the wild</span>');
  chips.push('<span class="chip">' + (d.direct ? 'direct' : 'transitive') +
    (d.rel === 'dev' ? ', dev' : d.rel === 'ci_uses' ? ', CI' : '') + '</span>');
  if (d.ecosystem) chips.push('<span class="chip">' + esc(d.ecosystem) + '</span>');
  if (d.shared > 1) chips.push('<span class="chip">in ' + d.shared + ' projects</span>');
  if (d.kind !== 'project') {
    chips.push(cluster && cluster.github
      ? '<span class="chip dep" title="On GitHub as ' + esc(cluster.github) +
        ' — Dependabot can raise this if it is switched on there">dependabot</span>'
      : '<span class="chip nodep" title="Not a GitHub repo — Dependabot will never ' +
        'raise this">no dependabot</span>');
  }

  const body = advisories.length ? advisories.map(a => {
    const bits = [];
    if (a.sev) bits.push('<span class="sev" style="color:' +
      (SEV_COLOR[a.sev] || 'var(--muted)') + '">' + esc(a.sev) + '</span>');
    if (a.cvss != null) bits.push('<span class="chip">CVSS ' + a.cvss + '</span>');
    if (a.epss != null) bits.push('<span class="chip">EPSS ' +
      (a.epss * 100).toFixed(1) + '%</span>');
    if (a.cve) bits.push('<span class="chip">' + esc(a.cve) + '</span>');
    if (a.kev) bits.push('<span class="chip kev">KEV</span>');
    const link = a.url
      ? '<a href="' + esc(a.url) + '" target="_blank" rel="noopener">' +
        esc(a.id || a.cve || 'advisory') + '</a>'
      : '<span>' + esc(a.id || 'advisory') + '</span>';
    return '<div class="adv"><div class="meta">' + link + bits.join('') + '</div>' +
      '<div class="sum">' + esc(a.sum || '') + '</div>' +
      (a.range ? '<div class="rng">vulnerable: ' + esc(a.range) + '</div>' : '') +
      '</div>';
  }).join('') : '<div class="hint">No advisory matched this package — it is shown for ' +
    'context as part of this dependency set.</div>';

  const fix = d.fix
    ? '<div class="fix"><div class="chip" style="border:0;padding-left:0">Fix</div>' +
      '<code>cd ' + esc(cluster ? cluster.path : '') + '\n' + esc(d.fix) + '</code>' +
      '<button id="copyfix">Copy command</button> ' +
      '<button id="copyai">Copy AI prompt</button></div>'
    : '';

  drawer.innerHTML = '<button class="close" id="drawerclose" aria-label="Close">&times;</button>' +
    '<h2>' + esc(d.name) + '</h2>' +
    '<div class="jump">' + esc(d.version || '') +
    (d.target ? ' &rarr; <span class="to">' + esc(d.target) + '</span>'
              : ' <span style="color:var(--muted)">&rarr; no fix published</span>') + '</div>' +
    '<div class="chips">' + chips.join('') + '</div>' +
    (d.kind === 'project' ? '' :
      '<div class="hint">Dependabot raises these only for repos on GitHub, and only ' +
      'if it is switched on for that repo.</div>') +
    body + fix;
  drawer.classList.add('open');
  relayout();

  document.getElementById('drawerclose').onclick = closeDrawer;
  const copy = document.getElementById('copyfix');
  if (copy) {
    copy.onclick = () => {
      navigator.clipboard.writeText('cd ' + (cluster ? cluster.path : '') + '\n' + d.fix)
        .then(() => {
          copy.textContent = 'Copied';
          setTimeout(() => copy.textContent = 'Copy command', 1500);
        });
    };
  }
  const ai = document.getElementById('copyai');
  if (ai) {
    ai.onclick = () => {
      navigator.clipboard.writeText(aiPrompt(d, cluster)).then(() => {
        ai.textContent = 'Copied';
        setTimeout(() => ai.textContent = 'Copy AI prompt', 1500);
      });
    };
  }
}

/// Evidence for a coding agent, which decides whether the upgrade is warranted.
function aiPrompt(d, cluster) {
  const lines = [];
  lines.push('A dependency scan flagged `' + d.name + ' ' + (d.version || '') +
    '` in the repository at `' + (cluster ? cluster.path : '') + '`.');
  lines.push('');
  lines.push('Work out whether this codebase is genuinely exposed, then apply the upgrade ' +
    'only if it is warranted. The scanner matches installed versions against published ' +
    'advisory ranges and knows nothing about how this code uses the package.');
  lines.push('');
  lines.push('## Finding');
  lines.push('');
  lines.push('- Package: ' + d.name + ' ' + (d.version || '') +
    (d.target ? ' -> ' + d.target : ' (no published fix)'));
  lines.push('- Ecosystem: ' + (d.ecosystem || 'unknown'));
  lines.push('- Pulled in: ' + (d.direct ? 'direct' : 'transitive') +
    (d.rel === 'dev' ? ', dev-only' : d.rel === 'ci_uses' ? ', CI-only' : ''));
  lines.push('- Urgency: ' + (d.band || 'n/a'));
  if (d.kev) lines.push('- Known exploited in the wild (CISA KEV).');
  if (d.shared > 1) lines.push('- Also present in ' + d.shared + ' other projects.');
  lines.push('');
  lines.push('## Advisories');
  lines.push('');
  (d.adv || []).forEach(a => {
    const bits = [a.sev, a.cvss != null ? 'CVSS ' + a.cvss : null, a.cve]
      .filter(Boolean).join(', ');
    lines.push('- ' + (a.id || a.cve || 'advisory') + (bits ? ' (' + bits + ')' : ''));
    if (a.sum) lines.push('  ' + a.sum);
    if (a.range) lines.push('  vulnerable range: ' + a.range);
    if (a.url) lines.push('  ' + a.url);
  });
  lines.push('');
  lines.push('## How to work through it');
  lines.push('');
  lines.push('1. Find where this package is used here. If it is transitive, identify the ' +
    'direct dependency that owns it.');
  lines.push('2. Decide whether the vulnerable code path is reachable, and say why in a ' +
    'sentence or two. A dev-only or build-time dependency is often not urgent.');
  lines.push('3. If warranted, apply the smallest bump that clears the advisory' +
    (d.fix ? ' (suggested: `' + d.fix + '`)' : '') + '.');
  lines.push('4. Check the changelog for breaking changes and adjust call sites.');
  lines.push('5. Run install, lint, type-check, build and tests. Report failures honestly.');
  lines.push('6. Summarise what you changed, what you left alone and why.');
  lines.push('');
  lines.push('Do not commit or push. Leave the changes in the working tree for review.');
  return lines.join('\n');
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

function drawList() {
  const list = document.getElementById('plist');
  const rows = DATA.clusters.filter(c => mode === 'all' || c.affected > 0);
  list.innerHTML = rows.map(c =>
    '<div class="proj" data-id="' + esc(c.id) + '" aria-selected="' +
    (focus === c.id) + '" title="' + esc(c.path) + '">' +
    '<i class="dot" style="background:' + (c.band ? COLOR[c.band] : 'var(--clean)') + '"></i>' +
    '<span class="nm">' + esc(c.name) + '</span>' +
    '<span class="ct">' + (c.affected || '') + '</span></div>').join('');
  [...list.querySelectorAll('.proj')].forEach(el => {
    el.onclick = () => select(el.dataset.id === focus ? null : el.dataset.id);
  });
}

function select(id) {
  // A project with no cluster here (filtered out, or not in this scan) would otherwise
  // leave an empty canvas; fall back to the full view instead.
  if (id && !clusterById.has(id)) { id = null; }
  focus = id;
  // A focused cluster lays out at the origin. Without reseeding, its nodes keep the
  // coordinates they had in the full grid and fly in from off-screen, so the view
  // looks empty for a second after every selection.
  if (id) {
    DATA.nodes.forEach(n => {
      if (n.cluster === id) {
        n.x = (Math.random() - 0.5) * 60;
        n.y = (Math.random() - 0.5) * 60;
        n.vx = 0;
        n.vy = 0;
      }
    });
  }
  render();
  fit();
}

function fit() {
  const active = visibleClusters();
  if (!active.length) return;
  const solo = active.length === 1;
  const box = document.getElementById('canvas').getBoundingClientRect();
  let minX, maxX, minY, maxY;

  // One focused cluster can hold 5 nodes or 50, so measure where the nodes actually
  // are rather than assuming a radius. Falls back to the centroid before the first tick.
  const pts = solo ? sim.nodes().filter(n => isFinite(n.x) && isFinite(n.y)) : [];
  if (pts.length > 1) {
    const pad = 55;
    minX = Math.min.apply(null, pts.map(n => n.x)) - pad;
    maxX = Math.max.apply(null, pts.map(n => n.x)) + pad;
    minY = Math.min.apply(null, pts.map(n => n.y)) - pad;
    maxY = Math.max.apply(null, pts.map(n => n.y)) + pad;
  } else {
    const pad = solo ? 90 : 150;
    const xs = active.map(c => c.cx), ys = active.map(c => c.cy);
    minX = Math.min.apply(null, xs) - pad;
    maxX = Math.max.apply(null, xs) + pad;
    minY = Math.min.apply(null, ys) - pad;
    maxY = Math.max.apply(null, ys) + pad;
  }

  const k = Math.min(box.width / (maxX - minX), box.height / (maxY - minY),
                     solo ? 3.0 : 1.6);
  const to = d3.zoomIdentity.scale(k).translate(-(minX + maxX) / 2, -(minY + maxY) / 2);
  // A transition is frame-driven like the simulation: with no frames it never starts and
  // the view keeps the identity transform, which is its own kind of blank pane.
  if (stalled || document.hidden) svg.call(zoom.transform, to);
  else svg.transition().duration(400).call(zoom.transform, to);
}

function resize() {
  const box = document.getElementById('canvas').getBoundingClientRect();
  const w = Math.max(1, Math.round(box.width));
  const h = Math.max(1, Math.round(box.height));
  // Set width/height as attributes rather than leaning on width:100%. Docking the
  // drawer resizes this flex container, and a percentage-sized SVG lets WebKit keep
  // the old compositing tile, which paints a clipped ghost of the previous layout
  // beside the live one. An explicit box makes the resize a real layout change.
  svg.attr('width', w).attr('height', h)
     .attr('viewBox', [-w / 2, -h / 2, w, h]);
}
window.addEventListener('resize', resize);
// Coming back on screen restores animation frames, so the next render can animate again.
document.addEventListener('visibilitychange', () => { if (!document.hidden) stalled = false; });

document.getElementById('t-aff').onclick = () => setMode('affected');
document.getElementById('t-all').onclick = () => setMode('all');
document.getElementById('t-reset').onclick = () => { focus = null; closeDrawer(); render(); fit(); };
function setMode(m) {
  mode = m;
  focus = null;
  document.getElementById('t-aff').setAttribute('aria-pressed', String(m === 'affected'));
  document.getElementById('t-all').setAttribute('aria-pressed', String(m === 'all'));
  render();
  fit();
}

sim.on('end', () => { if (visibleClusters().length === 1) fit(); });

resize();
render();
setTimeout(fit, 60);
</script>
</body>
</html>
"""


def render_html(data, rows, leads, graph, title, home):
    nodes, edges, clusters, hidden = build_render_graph(graph, rows, leads, home)
    counts = data.get("counts", {})
    stats = data.get("graph_stats", {})
    intel = data.get("intel", {})
    affected = sum(1 for c in clusters if c["affected"])
    subtitle = (f"{affected} of {stats.get('projects', 0)} projects affected · "
                f"{stats.get('packages', 0)} packages scanned · "
                f"advisories since {intel.get('published_since')} · "
                + ", ".join(f"{b} {counts.get(b, 0)}" for b, _, _ in BANDS))
    # Advisory text can contain "</script>" — one of them is literally about unescaped
    # "</style>" — which would close this tag early. Escaping the slash is the standard
    # guard and stays valid JSON.
    payload = json.dumps({"nodes": nodes, "edges": edges, "clusters": clusters,
                          "hidden": hidden}).replace("</", "<\\/")
    return (HTML_TEMPLATE
            .replace("__D3__", d3_script())
            .replace("__DATA__", payload)
            .replace("__TITLE__", html.escape(title))
            .replace("__SUBTITLE__", html.escape(subtitle)))


def main():
    ap = argparse.ArgumentParser(description="Render the radar report")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--title", default="Vulnerability radar")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
    rows = group_findings(data.get("findings", []))
    projects = by_project(rows)
    leads = data.get("leads", [])
    home = str(Path.home())

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.md").write_text(
        render_markdown(data, rows, projects, home, project_nodes(graph)),
                                      encoding="utf-8")
    (outdir / "graph.html").write_text(
        render_html(data, rows, leads, graph, args.title, home), encoding="utf-8")
    (outdir / "graph.mmd").write_text(render_mermaid(rows, home), encoding="utf-8")

    if not args.quiet:
        print(f"report: {outdir / 'report.md'}")
        print(f"graph:  {outdir / 'graph.html'}")
        print(f"projects affected: {len(projects)}")
        for band, title, _ in BANDS:
            hits = [p for p in projects if p["band"] == band]
            if hits:
                top = ", ".join(p["name"] for p in hits[:4])
                print(f"  {band} {title}: {len(hits)} project(s) — {top}"
                      + (" …" if len(hits) > 4 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
