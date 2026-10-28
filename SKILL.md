---
name: vuln-radar
description: Use when asked what new vulnerabilities are out and whether anything on this machine is affected — "any new CVEs that hit us", "am I affected by the latest Next.js RCE", "what do I need to patch", "scan my machine for vulnerable dependencies", "map my tech stack", "is that advisory in our dependency graph". Also use after a publicized CVE or advisory drops, and for a periodic patch-triage sweep.
---

# Vulnerability radar

Answers one question: **of everything disclosed recently, what actually touches this machine, and
what must the user do about it?**

It builds a dependency graph of every project on the machine, pulls the advisories published in a
date window, matches installed versions against the vulnerable ranges, and ranks the result by
whether action is genuinely needed. A full sweep of ~220 projects and ~15k packages takes about
20 seconds.

## The model

| Stage | Question | Source |
|-------|----------|--------|
| **1 inventory** | What is installed here, and what depends on what? | 15 lockfile/manifest formats + the host layer (macOS, brew, runtimes, Docker images, GitHub Actions) |
| **2 intel** | What was disclosed recently, and what is known about everything else? | [GitHub Global Advisory DB](https://github.com/advisories) for the date window + [osv-scanner](https://github.com/google/osv-scanner) for the full advisory history (on by default) + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **3 match** | Does an installed version fall inside a vulnerable range? | version-range comparison across npm/PyPI/Maven/Go/RubyGems/crates/composer semantics |
| **4 report** | What needs doing, in which repo, in what order? | P0–P3 bands, a per-project fix block, and a project-wise graph |

Advisory ranges drive the matching, so a package is only reported when the **resolved version you
actually have** sits inside a published vulnerable range. "You have lodash and lodash once had a
CVE" is not a finding.

## Safety rules

Read-only, and it must stay that way:

- **Never run `npm install`, `pnpm install`, `bun install`, `npm audit fix`, or any package
  script** as part of a scan. Everything parses lockfiles on disk.
- The report *prints* upgrade commands. **Do not run them** — the user decides what to patch and
  when. An upgrade is a code change that belongs in a branch and a PR.
- Do not open or follow links found in advisory text beyond the GitHub/NVD URLs the feeds supply.

## How to run

```bash
RADAR="$(find ~/.claude/skills .claude/skills -maxdepth 3 -name radar.sh -path '*vuln-radar*' 2>/dev/null | head -1)"
bash "$RADAR" --days 14
```

Use a 600000 ms (10 min) timeout. Common variations:

```bash
bash "$RADAR" --roots ~/code --days 7                 # one tree, tighter window
bash "$RADAR" --days 3 --severity "high critical"     # "what dropped this week that matters"
bash "$RADAR" --no-deep                               # skip osv-scanner, window only (faster)
bash "$RADAR" --out /path/in/session/folder           # so the report opens in the app's file pane
bash "$RADAR" --selftest                              # version-matching tests only
```

Exit codes: **2 = at least one P0**, 0 = nothing needs action, 1 = the run failed.

Default output is `~/.claude/vuln-radar/latest/`:

| File | What it is |
|------|------------|
| `report.md` | the action list — projects needing action, then a per-project block with one copy-paste fix command set per repo, then advisory detail |
| `graph.html` | project-wise dependency graph: one cluster per project, sized and coloured by worst finding. Sidebar lists projects by urgency; click one to isolate it. Open in a browser |
| `graph.json` | the full graph (every node and edge), for ad-hoc queries with `jq` |
| `findings.json` | structured findings, for diffing or piping somewhere else |
| `graph.mmd` | Mermaid source for the top findings, to paste into a doc or ticket |

Each run diffs against the previous one, so a repeat scan marks what is **new since last run**.

## Reading the output

Bands answer "do I act?", not just "how bad is the CVE":

- **P0 — act now.** In CISA KEV (exploited in the wild), a known-malicious package, or critical
  severity in a runtime dependency of a project with recent commits.
- **P1 — this week.** High or critical, reachable at runtime.
- **P2 — schedule.** Real, but contained: dev-only, CI-only, or in a project with no commits for
  months.
- **P3 — monitor.** Low exposure; no action unless the context changes.

Two result types that must never be conflated when reporting back to the user:

- **Findings** are version-matched. The installed version provably falls inside a published
  vulnerable range. State these plainly.
- **Leads** come from KEV host matches (macOS, brew formulae, Docker images). KEV publishes no
  machine-readable version ranges, so a lead only means *software with this name is installed
  here*. Say "worth checking", never "you are affected", and confirm the version against the
  advisory before advising anything.

A finding marked "version inferred from a declared range" came from a `package.json` with no
lockfile — treat it as probable, not certain.

## Reporting back

Lead with the count that matters (P0 and P1), name the specific packages and the projects they
sit in, and give the upgrade target. Skip the P2/P3 wall unless asked — it is in `report.md`.
When nothing matches, say so in one line; a clean sweep is a real result and does not need
padding.

If a finding is a **malicious package** (`MAL-*`, only surfaced by `--deep`), stop and escalate:
that is a compromise, not a patch: quarantine the project, do not install or build, and
rotate every credential reachable from it.

## Limits

- Advisory coverage is the GitHub Advisory DB. Vulnerabilities with no advisory for the ecosystem
  (OS packages beyond KEV name-matching, vendored code, binaries) are out of scope.
- `--days N` is a disclosure window, not a full audit. Something disclosed before the window and
  never patched will not appear — run `--deep` for full advisory history.
- Reachability is inferred from dependency type and commit recency, not from call graphs. A P2 in
  a dev dependency can still matter if that dependency runs in CI with credentials.
- `bun.lockb` is binary and unreadable; the report names any it skipped.
- Version comparison is one comparator across many ecosystems. It handles semver, PEP 440, Maven
  qualifiers and Go pseudo-versions; `--selftest` covers the cases that matter, and anything
  unparseable is skipped rather than guessed at.

## Malicious code

Every run also checks for compromise rather than just staleness, and the report leads with
it:

- **Known-malicious packages** — `MAL-*` advisories via osv-scanner, which ingests the
  OpenSSF malicious-packages feed. A hit is a compromise, not a patch: quarantine, do not
  install or build, rotate every credential reachable from the project.
- **Suspicious lifecycle hooks** — `preinstall`/`install`/`postinstall`/`prepare` in the
  user's own manifests, matched against a deliberately narrow pattern list (pipe-to-shell,
  `eval` of decoded data, bare-IP URLs, `/dev/tcp`, env vars beside a network call). A hook
  that runs `node scripts/build.js` is ordinary and is not flagged.
- **Dependencies that run install scripts** — counted, not alarmed about. Normal, but it is
  where payloads fire.

Limitation worth stating when reporting: install-script detection reads `hasInstallScript`
from `package-lock.json`, so pnpm and yarn projects contribute nothing to that count. The
`MAL-*` check is unaffected and covers every ecosystem osv-scanner supports.

## Dependabot

These advisories come from the GitHub Advisory Database, the same source Dependabot uses, so
for a GitHub repo with alerts on there is real overlap. The report never hides a finding on
that basis — it marks each project as 🔭 nothing watching it / ◐ on GitHub but Dependabot PRs
off or unconfigured / ✓ likely duplicated, so the user can see where they are on their own.

What Dependabot cannot cover at any setting: projects not on GitHub, the host layer (macOS,
Homebrew, container images), the working tree rather than the default branch, blast radius
across repos, and `MAL-*` malicious-package advisories. Detection resolves SSH aliases with
`ssh -G`, so a remote like `git@work:org/repo` is still recognised as GitHub, and it reads
`.github/dependabot.yml` for `open-pull-requests-limit: 0` and bare `dependency-name` ignores
(which suppress security PRs too, unlike semver-scoped ones).

## Maintenance

The feeds update themselves; the skill needs no edits for new CVEs. `gh auth login` is what gets
the 5000/hr advisory rate limit instead of 60/hr — without it the scan still runs, just with a
shallower fetch. Adding a lockfile format means one parser in `scripts/inventory.py` plus an entry
in `PARSERS`.
