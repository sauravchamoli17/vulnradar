# Vulnerability Radar

A macOS menu bar app and CLI that answers one question: **of the vulnerabilities disclosed
recently, which ones actually touch code on my machine, and what do I do about them?**

Most scanners answer "does this repo have CVEs" one repo at a time. This starts from the
advisory feed, builds a dependency graph of every project you have, and tells you which of
your projects a new advisory lands in. A sweep of ~220 projects and ~15,000 packages takes
about 20 seconds.

- **Version ranges, not names.** A package is reported only when the version you actually
  have falls inside a published vulnerable range.
- **Ranked by whether you must act.** A critical in a dev dependency of an abandoned repo is
  P2. A high in a runtime dependency you shipped last week is P1. Anything in CISA KEV is P0.
- **Per project, not per advisory.** A package can be installed in one checkout and merely
  pinned in twenty others. Each project is ranked on its own exposure, so the old clones in
  your home folder stop burying the repo you worked in this morning.
- **Honest about what it doesn't know.** Version-matched findings are kept apart from KEV
  host name-matches, which need a human to confirm.
- **Local.** The only outbound calls are the GitHub Advisory API and the CISA KEV catalog.

## Install

```bash
brew install --cask sauravchamoli17/tap/vulnradar
```

Or grab `VulnRadar.dmg` from [Releases](../../releases). The build is ad-hoc signed, not
notarised, so macOS blocks the first launch — right-click → **Open**, or
`xattr -dr com.apple.quarantine /Applications/VulnRadar.app`.

To build it yourself: `cd app && bash build.sh`. Needs the Xcode Command Line Tools and
nothing else — no project file, no package manager, no dependencies.

## Use

The app sits in the menu bar and badges the number of findings that need action now. Open it
for the project list, per-project fix commands, a **Fix with AI** prompt carrying the advisory
evidence, and a graph where every project is a cluster coloured by its worst finding.

Settings picks the folders to scan and the folders to skip — old clients and archives you
no longer work on, excluded whichever scope you chose. Scans can run on a clock ("every
weekday at 09:00"), with or without the app open.

It is also a plain CLI:

```bash
bash scripts/radar.sh --days 14                 # everything in your home folder
bash scripts/radar.sh --roots ~/code --days 7   # one tree, tighter window
bash scripts/radar.sh --ignore ~/old-clients "*/Archive/*"   # skip what you left behind
bash scripts/radar.sh --no-deep                 # skip osv-scanner, advisory window only
bash scripts/radar.sh --selftest                # version-matching tests
```

Exit `2` = at least one P0, `0` = nothing to do, `1` = the run failed, so it works as a CI
gate. Output lands in `~/.claude/vuln-radar/latest/`: `report.md`, `graph.html`,
`findings.json`, `graph.json`.

Drop the directory into `~/.claude/skills/` and Claude Code picks it up as `/vuln-radar`.

## How it works

| Stage | Question | Source |
|-------|----------|--------|
| **inventory** | What is installed, and what depends on what? | 15 lockfile/manifest formats + the host layer (macOS, Homebrew, runtimes, Docker images, GitHub Actions) |
| **intel** | What is known? | GitHub Global Advisory DB for the window, osv-scanner for full history, CISA KEV |
| **match** | Is an installed version inside a vulnerable range? | one comparator across npm/PyPI/Maven/Go/RubyGems/crates/composer |
| **report** | What needs doing, in what order? | P0–P3 bands, per-project fix blocks, a graph |

Each stage is a standalone script you can re-run on its own.

## Isn't this just Dependabot?

Partly, and the report says so rather than pretending otherwise — each finding is marked for
whether Dependabot would raise it. What Dependabot cannot reach at any setting: projects not
on GitHub, the host layer, your working tree rather than the default branch, blast radius
across repos, and `MAL-*` malicious-package advisories.

## Limits

Coverage is the GitHub Advisory DB, so vulnerabilities with no advisory for the ecosystem are
out of scope — except the Node.js runtime, which is version-matched against Node's own core
advisory database, since those CVEs carry no package ecosystem and no package upgrade clears
them. Other runtimes and OS packages are still name-matched leads only. Reachability is inferred from dependency type, commit recency and whether the
dependency tree is on disk, not from call graphs. That last signal only works for ecosystems
that install into the project (npm, Composer, bundled Ruby) — Go, Maven, Cargo and a default
pip resolve into shared caches, so they are left unknown rather than called clean. `bun.lockb` is binary and unreadable; the report names any it skipped.

Adding a lockfile format is one parser in `scripts/inventory.py` plus an entry in `PARSERS`.
Version-matching changes need cases in `scripts/vercmp.py` — run `--selftest`.

## License

MIT. See [LICENSE](LICENSE).
