#!/usr/bin/env bash
# vuln-radar orchestrator: inventory -> intel -> match -> report.
# Read-only. Never installs anything and never runs a package script.
# Exit 0 = nothing needs action, 2 = at least one P0, 1 = the run failed.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${HOME}"
STATE_DIR="${HOME_DIR}/.claude/vuln-radar"
OUT="${STATE_DIR}/latest"
ROOTS=()
IGNORE=()
DAYS=14
DEPTH=8
KEV_DAYS=90
DEEP=1
NO_HOST=0
SEVERITY=""
TITLE="Vulnerability radar"

usage() {
  cat <<'USAGE'
Usage: radar.sh [options]

  --roots DIR               directory to inventory, repeat for more (default: $HOME)
  --ignore PATTERN          skip a folder path, a bare directory name to prune
                            anywhere, or a glob matched against the full path;
                            repeat for more
  --days N                  advisory publication window   (default: 14)
  --depth N                 directory walk depth          (default: 8)
  --kev-days N              KEV window for host leads     (default: 90)
  --severity "high critical"  only fetch these severities
  --deep                    run osv-scanner for full advisory history (default)
  --no-deep, --fast         skip osv-scanner; match only the advisory window
  --no-host                 skip the host layer (brew, runtimes, images)
  --out DIR                 output directory               (default: ~/.claude/vuln-radar/latest)
  --title "..."             title for the rendered graph
  --selftest                run the version-matching and ignore tests, then exit
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --roots) ROOTS+=("$2"); shift 2 ;;
    --ignore) IGNORE+=("$2"); shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --kev-days) KEV_DAYS="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --deep) DEEP=1; shift ;;
    --no-deep|--fast) DEEP=0; shift ;;
    --no-host) NO_HOST=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --title) TITLE="$2"; shift 2 ;;
    --selftest)
      python3 "${SCRIPT_DIR}/vercmp.py" || exit 1
      python3 "${SCRIPT_DIR}/inventory.py" --selftest || exit 1
      exec python3 "${SCRIPT_DIR}/match.py" --selftest ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
  echo "vuln-radar needs python3 (3.11+ for TOML lockfiles)" >&2
  exit 1
fi
[ ${#ROOTS[@]} -gt 0 ] || ROOTS=("$HOME_DIR")

mkdir -p "$OUT" "$STATE_DIR"
# State lives beside the output, so a scoped scan never diffs against a
# whole-machine one.
PREV="${OUT}/previous-findings.json"

step() { printf '\n== %s\n' "$1"; }

step "1/4 inventory  (roots: ${ROOTS[*]}, depth ${DEPTH}${IGNORE:+, ignoring: ${IGNORE[*]}})"
INVENTORY=(--roots "${ROOTS[@]}" --depth "$DEPTH")
[ "$NO_HOST" -eq 1 ] && INVENTORY+=(--no-host)
[ ${#IGNORE[@]} -gt 0 ] && INVENTORY+=(--ignore "${IGNORE[@]}")
"$PY" "${SCRIPT_DIR}/inventory.py" "${INVENTORY[@]}" \
  --out "${OUT}/graph.json" || { echo "inventory failed" >&2; exit 1; }

step "2/4 intel      (advisories published in the last ${DAYS} days + CISA KEV)"
INTEL=(--days "$DAYS" --graph "${OUT}/graph.json")
if [ -n "$SEVERITY" ]; then
  # A severity is always one word, so the documented space-separated form is safe to split.
  read -r -a SEVERITIES <<< "$SEVERITY"
  INTEL+=(--severity "${SEVERITIES[@]}")
fi
"$PY" "${SCRIPT_DIR}/intel.py" "${INTEL[@]}" \
  --out "${OUT}/intel.json" || { echo "intel fetch failed" >&2; exit 1; }

OSV_RESULTS=""
if [ "$DEEP" -eq 1 ]; then
  if command -v osv-scanner >/dev/null 2>&1; then
    step "2b/4 osv-scanner (every advisory ever, not just the window)"
    # Hand osv-scanner the project directories the inventory already found. Pointing
    # it at a whole home folder makes it walk from / through every node_modules and
    # cache, which never finishes.
    "$PY" - "${OUT}/graph.json" > "${OUT}/projdirs.txt" <<'DIRS'
import json, sys
graph = json.load(open(sys.argv[1]))
for node in graph["nodes"]:
    if node.get("kind") == "project" and node.get("path"):
        print(node["path"])
DIRS
    PROJDIRS=()
    while IFS= read -r dir; do
      [ -n "$dir" ] && PROJDIRS+=("$dir")
    done < "${OUT}/projdirs.txt"
    rm -f "${OUT}/projdirs.txt"
    PARTS=()
    i=0
    # osv-scanner takes the directories as arguments, so feed it a slice at a time
    # rather than all of them at once.
    while [ "$i" -lt ${#PROJDIRS[@]} ]; do
      part="${OUT}/osv.part$((i / 40)).json"
      osv-scanner scan source "${PROJDIRS[@]:i:40}" --format json --output "$part" >/dev/null 2>&1
      [ -s "$part" ] && PARTS+=("$part")
      i=$((i + 40))
    done
    if [ ${#PARTS[@]} -gt 0 ]; then
      "$PY" - "${OUT}/osv.json" "${PARTS[@]}" <<'MERGE'
import json, sys
out, parts = sys.argv[1], sys.argv[2:]
results = []
for part in parts:
    try:
        results.extend(json.load(open(part)).get("results") or [])
    except (OSError, ValueError):
        pass
json.dump({"results": results}, open(out, "w"))
print(f"osv-scanner: merged {len(results)} source result(s)")
MERGE
      rm -f "${OUT}"/osv.part*.json
      OSV_RESULTS="${OUT}/osv.json"
    else
      echo "osv-scanner produced no results"
    fi
  else
    echo "osv-scanner not found — install it (brew install osv-scanner) for full"
    echo "advisory history; continuing with the advisory window only"
  fi
fi

step "3/4 match      (version ranges against the graph)"
MATCH=(--graph "${OUT}/graph.json" --intel "${OUT}/intel.json" --kev-days "$KEV_DAYS")
[ -f "$PREV" ] && MATCH+=(--state "$PREV")
[ -n "$OSV_RESULTS" ] && MATCH+=(--osv-results "$OSV_RESULTS")
"$PY" "${SCRIPT_DIR}/match.py" "${MATCH[@]}" --out "${OUT}/findings.json" \
  || { echo "match failed" >&2; exit 1; }

step "4/4 report"
"$PY" "${SCRIPT_DIR}/report.py" --findings "${OUT}/findings.json" \
  --graph "${OUT}/graph.json" --outdir "$OUT" --title "$TITLE" \
  || { echo "report failed" >&2; exit 1; }

cp "${OUT}/findings.json" "$PREV" 2>/dev/null || true

P0=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["counts"]["P0"])' \
  "${OUT}/findings.json" 2>/dev/null || echo 0)
printf '\n== done\nreport: %s\ngraph:  %s\n' "${OUT}/report.md" "${OUT}/graph.html"
if [ "${P0:-0}" -gt 0 ]; then
  printf 'P0: %s advisory match(es) need action — read the "Act now" section.\n' "$P0"
  exit 2
fi
exit 0
