#!/usr/bin/env bash
# M33 Phase B3 (design decision 2026-11-09): re-run of faults 2, 3, 6 against the NOW-WIRED features -
# SoakHost registers AddCredProxThrottling + AddCredProxResilience and both config sections
# key the live `vendor` cluster; the rotate lever now swaps kv_list with a bumped
# attributes.updated so the provider's change-detection actually fires (B2 triage, report
# §5 entry 3). Faults 7 and the toxic/file-lever set keep their artifacts of record.
# CRITICAL vs phase-b2: the soakhost IMAGE is built before `up` - phase scripts never
# rebuilt it, so the B2 image carried the un-wired host. Same watchdog, journal reset/save,
# secret-scan and abort doctrine. Judges the published CredProx package pinned in SoakHost.csproj (shipped behaviour).
# Usage: phase-b3.sh   (env overrides: WINDOW_MINUTES=5 VUS=20)
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WINDOW_MINUTES="${WINDOW_MINUTES:-5}"
VUS="${VUS:-20}"

RUN="/tmp/m33-soak-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN/journal" "$RUN/faults" "$RUN/logs"; touch "$RUN/stats.csv" "$RUN/k6-line.csv"
chmod 777 "$RUN"; chmod 666 "$RUN/k6-line.csv" "$RUN/stats.csv" "$RUN/k6-summary.json" 2>/dev/null
"$HERE/scripts/init-secrets.sh" "$RUN" || { echo "INIT-FAIL"; exit 1; }
export SOAK_RUN_DIR="$RUN" SOAK_VUS="$VUS"
cd "$HERE/compose" || exit 2

cleanup() {
  docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
  curl -fsS http://127.0.0.1:18081/__admin/requests | gzip > "$RUN/journal/wiremock-final.json.gz" 2>/dev/null
  bash "$HERE/scripts/teardown.sh"
}
trap cleanup EXIT

# Fresh bits, twice over (B3 probe lesson): the Dockerfile is a runtime-only COPY of the
# HOST publish output - editing Program.cs changes nothing until `dotnet publish` runs -
# and `docker compose build` cannot be used either (its context ../.. resolves to tools/,
# doubling the dockerfile prefix). Publish first, then build via the README's shape.
dotnet publish "$HERE/SoakHost" -c Release -o "$HERE/build/publish" \
  || { echo "PUBLISH-FAIL"; exit 1; }
docker build -f "$HERE/SoakHost/Dockerfile" -t credprox-soakhost:local "$HERE/../.." \
  || { echo "BUILD-FAIL"; exit 1; }
docker compose up -d toxiproxy wiremock soakhost || { echo "UP-FAIL"; exit 1; }
for _ in $(seq 1 90); do
  curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:18080/healthz >/dev/null || { echo "HEALTH-FAIL (see: docker compose logs soakhost)"; exit 1; }
# Remove the startup-loaded scenario-gated mappings (now 5 incl. kv_list_bumped): forced
# scenario state cannot be reset in 3.9.2, so those copies must never shadow a swap.
python3 -I - <<'PY' || { echo "SCENARIO-STRIP-FAIL"; exit 1; }
import json, urllib.request
W = 'http://127.0.0.1:18081'
def req(m, p):
    r = urllib.request.Request(W + p, method=m)
    with urllib.request.urlopen(r) as x:
        return x.read().decode()
ms = json.loads(req('GET', '/__admin/mappings'))['mappings']
ids = [m['id'] for m in ms if m.get('scenarioName')]
for i in ids:
    req('DELETE', '/__admin/mappings/' + i)
print('SCENARIO-MAPPINGS-REMOVED', len(ids))
PY
echo "PHASE-B3-START dir=$RUN window=${WINDOW_MINUTES}m faults=2,3,6"

TOTAL=$(( 12 * WINDOW_MINUTES + 60 ))
(
  end=$(( $(date +%s) + TOTAL * 60 ))
  tick=0
  while [ "$(date +%s)" -lt "$end" ]; do
    sleep 60
    tick=$((tick + 1))
    for c in m33-soak-soakhost-1 m33-soak-wiremock-1 m33-soak-toxiproxy-1; do
      st="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo gone)"
      if [ "$st" != running ]; then
        echo "WATCHDOG-CONTAINER-DEAD $c=$st at $(date -u +%H:%M:%SZ)"
        touch "$RUN/ABORT"
        docker compose stop k6 >/dev/null 2>&1
        exit 0
      fi
    done
    if [ $((tick % 30)) -eq 0 ]; then
      load5="$(awk '{print int($1)}' /proc/loadavg)"
      echo "watchdog: 5-min load $load5"
      if [ "$load5" -gt 40 ]; then
        echo "BACKOFF: load $load5 > 40 - stopping load generator"
        touch "$RUN/ABORT"
        docker compose stop k6 >/dev/null 2>&1
        pkill -f 'k6 run /k6/soak.js' 2>/dev/null
        exit 0
      fi
    fi
  done
) &
WATCH=$!

aborted() { [ -f "$RUN/ABORT" ]; }
jreset() { curl -fsS -X DELETE http://127.0.0.1:18081/__admin/requests >/dev/null 2>&1 \
             || echo "WARN journal-reset-failed (witness may see previous window)"; }
jsave() { curl -fsS http://127.0.0.1:18081/__admin/requests | gzip > "$RUN/journal/journal-$1.json.gz"; }

k6_window() {
  SOAK_MINUTES="$WINDOW_MINUTES" docker compose --profile load run --rm k6 \
    && cp "$RUN/k6-summary.json" "$RUN/faults/k6-summary-$1.json" 2>/dev/null
}

run_fault() { # run_fault <label> <lever>
  local label="$1" lever="$2" out rc
  aborted && return 1
  echo "FAULT-$label-SET"
  # NO pipe into tee: a pipe swallows the lever's exit code (attempt #2 lesson).
  out="$(bash "$HERE/scripts/faults.sh" "$lever" set 2>&1)"; rc=$?
  printf '%s\n' "$out" >> "$RUN/faults/fault-log.txt"
  [ $rc -eq 0 ] || { echo "FAULT-$label-FAIL set (rc=$rc)"; return 1; }
  printf '%s\n' "$out" | grep -q 'swap-on' || echo "WARN no swap-on marker for $label"
  jreset
  k6_window "$label-window" || { aborted && echo "FAULT-$label-FAIL window (watchdog abort)"; echo "FAULT-$label-FAIL window"; return 1; }
  jsave "$label-window"
  echo "FAULT-$label-WINDOW-DONE"
  out="$(bash "$HERE/scripts/faults.sh" "$lever" clear 2>&1)"; rc=$?
  printf '%s\n' "$out" >> "$RUN/faults/fault-log.txt"
  [ $rc -eq 0 ] || { echo "FAULT-$label-FAIL clear (rc=$rc)"; return 1; }
  printf '%s\n' "$out" | grep -q 'swap-off' || echo "WARN no swap-off marker for $label"
  echo "FAULT-$label-CLEARED"
  jreset
  k6_window "$label-recovery" || { aborted && echo "FAULT-$label-FAIL recovery (watchdog abort)"; echo "FAULT-$label-FAIL recovery"; return 1; }
  jsave "$label-recovery"
  echo "FAULT-$label-RECOVERED"
  aborted && { echo "FAULT-$label-FAIL (watchdog abort)"; return 1; }
  docker compose logs --no-color --since 12m soakhost > "$RUN/faults/host-$label.log" 2>/dev/null
  bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "FAULT-$label-FAIL secret-scan"; return 1; }
  echo "FAULT-$label-SCAN-ZERO"
  echo "FAULT-$label-DONE"
}

set -- 2 vendor-429 3 vendor-5xx 6 rotate
while [ $# -gt 0 ]; do
  run_fault "$1" "$2" || { echo "PHASE-B3-ABORT at fault $1"; kill "$WATCH" 2>/dev/null; exit 1; }
  shift 2
done

docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
aborted && { echo "PHASE-B3-ABORT (watchdog fired before final scan)"; kill "$WATCH" 2>/dev/null; exit 1; }
bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "FINAL-SCAN-FAILED"; kill "$WATCH" 2>/dev/null; exit 1; }
echo "FINAL-SCAN-ZERO"
kill "$WATCH" 2>/dev/null
echo "PHASE-B3-DONE dir=$RUN"
