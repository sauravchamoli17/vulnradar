#!/usr/bin/env bash
# vuln-radar orchestrator: inventory -> intel -> match -> report.
# Read-only. Never installs anything and never runs a package script.
# Exit 0 = nothing needs action, 2 = at least one P0, 1 = the run failed.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${HOME}"
STATE_DIR="${HOME_DIR}/.claude/vuln-radar"
OUT="${STATE_DIR}/latest"
ROOTS=""
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

  --roots "<dir> [dir...]"  directories to inventory      (default: $HOME)
  --days N                  advisory publication window   (default: 14)
  --depth N                 directory walk depth          (default: 8)
  --kev-days N              KEV window for host leads     (default: 90)
  --severity "high critical"  only fetch these severities
  --deep                    run osv-scanner for full advisory history (default)
  --no-deep, --fast         skip osv-scanner; match only the advisory window
  --no-host                 skip the host layer (brew, runtimes, images)
  --out DIR                 output directory               (default: ~/.claude/vuln-radar/latest)
  --title "..."             title for the rendered graph
  --selftest                run the version-matching tests and exit
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --roots) ROOTS="$2"; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --kev-days) KEV_DAYS="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --deep) DEEP=1; shift ;;
    --no-deep|--fast) DEEP=0; shift ;;
    --no-host) NO_HOST=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --title) TITLE="$2"; shift 2 ;;
    --selftest) exec python3 "${SCRIPT_DIR}/vercmp.py" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
  echo "vuln-radar needs python3 (3.11+ for TOML lockfiles)" >&2
  exit 1
fi
[ -n "$ROOTS" ] || ROOTS="$HOME_DIR"

mkdir -p "$OUT" "$STATE_DIR"
# State lives beside the output, so a Steady-only scan never diffs
# against a whole-machine one.
PREV="${OUT}/previous-findings.json"

step() { printf '\n== %s\n' "$1"; }

step "1/4 inventory  (roots: ${ROOTS}, depth ${DEPTH})"
HOST_FLAG=""
[ "$NO_HOST" -eq 1 ] && HOST_FLAG="--no-host"
# shellcheck disable=SC2086
"$PY" "${SCRIPT_DIR}/inventory.py" --roots $ROOTS --depth "$DEPTH" $HOST_FLAG \
  --out "${OUT}/graph.json" || { echo "inventory failed" >&2; exit 1; }

step "2/4 intel      (advisories published in the last ${DAYS} days + CISA KEV)"
SEV_FLAG=""
[ -n "$SEVERITY" ] && SEV_FLAG="--severity $SEVERITY"
# shellcheck disable=SC2086
"$PY" "${SCRIPT_DIR}/intel.py" --days "$DAYS" --graph "${OUT}/graph.json" $SEV_FLAG \
  --out "${OUT}/intel.json" || { echo "intel fetch failed" >&2; exit 1; }

OSV_FLAG=""
if [ "$DEEP" -eq 1 ]; then
  if command -v osv-scanner >/dev/null 2>&1; then
    step "2b/4 osv-scanner (every advisory ever, not just the window)"
    PARTS=""
    i=0
    for root in $ROOTS; do
      part="${OUT}/osv.part${i}.json"
      # osv-scanner exits non-zero when it finds vulnerabilities, which is the normal case.
      osv-scanner scan source -r "$root" --format json --output "$part" >/dev/null 2>&1
      [ -s "$part" ] && PARTS="$PARTS $part"
      i=$((i + 1))
    done
    if [ -n "$PARTS" ]; then
      # shellcheck disable=SC2086
      "$PY" - "${OUT}/osv.json" $PARTS <<'MERGE'
import json, sys
out, parts = sys.argv[1], sys.argv[2:]
results = []
for part in parts:
    try:
        results.extend(json.load(open(part)).get("results") or [])
    except (OSError, ValueError):
        pass
json.dump({"results": results}, open(out, "w"))
print(f"osv-scanner: merged {len(results)} source result(s) from {len(parts)} root(s)")
MERGE
      rm -f "${OUT}"/osv.part*.json
      OSV_FLAG="--osv-results ${OUT}/osv.json"
    else
      echo "osv-scanner produced no results"
    fi
  else
    echo "osv-scanner not found — install it (brew install osv-scanner) for full"
    echo "advisory history; continuing with the advisory window only"
  fi
fi

step "3/4 match      (version ranges against the graph)"
STATE_FLAG=""
[ -f "$PREV" ] && STATE_FLAG="--state $PREV"
# shellcheck disable=SC2086
"$PY" "${SCRIPT_DIR}/match.py" --graph "${OUT}/graph.json" --intel "${OUT}/intel.json" \
  --kev-days "$KEV_DAYS" $STATE_FLAG $OSV_FLAG --out "${OUT}/findings.json" \
  || { echo "match failed" >&2; exit 1; }

step "4/4 report"
"$PY" "${SCRIPT_DIR}/report.py" --findings "${OUT}/findings.json" \
  --graph "${OUT}/graph.json" --outdir "$OUT" --title "$TITLE" \
  || { echo "report failed" >&2; exit 1; }

cp "${OUT}/findings.json" "$PREV" 2>/dev/null || true

P0=$("$PY" -c "import json,sys; print(json.load(open('${OUT}/findings.json'))['counts']['P0'])" 2>/dev/null || echo 0)
printf '\n== done\nreport: %s\ngraph:  %s\n' "${OUT}/report.md" "${OUT}/graph.html"
if [ "${P0:-0}" -gt 0 ]; then
  printf 'P0: %s advisory match(es) need action — read the "Act now" section.\n' "$P0"
  exit 2
fi
exit 0
