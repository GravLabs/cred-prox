#!/usr/bin/env bash
# M33 Phase B driver (plan §5.5): 270-min steady soak (warm-up included), then every fault
# as set -> 5-min load window -> clear -> 5-min recovery window -> secret-scan, in plan
# order 1a idp-slow / 1b idp-down / 2 vendor-429 / 3 vendor-5xx / 4 reset-mid / 5 reload-mix /
# 6 rotate / 7 clock-skew / 8 slowloris. Budget guard identical to run-soak (5-min load > 40
# backs off). Teardown on EVERY exit path. Markers are the contract - watch for *-DONE and
# *-FAIL lines; the exit code of this script is the wrapper's problem, the markers are truth.
# Usage: phase-b.sh   (env overrides: STEADY_MINUTES=270 WINDOW_MINUTES=5 VUS=20)
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
STEADY_MINUTES="${STEADY_MINUTES:-270}"
WINDOW_MINUTES="${WINDOW_MINUTES:-5}"
VUS="${VUS:-20}"

RUN="/tmp/m33-soak-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN/journal" "$RUN/faults"; touch "$RUN/stats.csv" "$RUN/k6-line.csv"
# the k6 container's user must be able to create the summary and append the CSV line
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

docker compose up -d toxiproxy wiremock soakhost || { echo "UP-FAIL"; exit 1; }
for _ in $(seq 1 90); do
  curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:18080/healthz >/dev/null || { echo "HEALTH-FAIL (see: docker compose logs soakhost)"; exit 1; }
echo "PHASE-B-START dir=$RUN steady=${STEADY_MINUTES}m window=${WINDOW_MINUTES}m"

TOTAL=$(( STEADY_MINUTES + 12 * (2 * WINDOW_MINUTES) + 30 ))
# Watchdog (incident 20261108-215247: WireMock OOMKilled at 1h50m and k6 drove a dead
# upstream for 45 more minutes because the load gate only evaluated at window end):
# EVERY 60 s check infra liveness; on any non-running infra container, stamp $RUN/ABORT,
# stop k6 immediately and let the main flow fail loud. Load check stays hourly.
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
    if [ $((tick % 60)) -eq 0 ]; then
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
# Per-window journal capture, gzipped (~55 MB raw -> a few MB gz per 5-min window).
# The ring is capped at 30k entries, so a window's journal is complete only after a reset.
jsave() { curl -fsS http://127.0.0.1:18081/__admin/requests | gzip > "$RUN/journal/journal-$1.json.gz"; }

k6_window() { # k6_window <label> ; VUs/duration fixed, summary collected per window
  SOAK_MINUTES="$WINDOW_MINUTES" docker compose --profile load run --rm k6 \
    && cp "$RUN/k6-summary.json" "$RUN/faults/k6-summary-$1.json" 2>/dev/null
}

# Steady soak (k6 summary is the soak's own; fault windows collect into faults/).
# SOAK_STRICT=1 arms k6's mid-run error-rate abort (see soak.js thresholds).
SOAK_MINUTES="$STEADY_MINUTES" SOAK_STRICT=1 docker compose --profile load run --rm k6
if [ $? -ne 0 ]; then
  aborted && echo "K6-STEADY-FAIL (watchdog abort)" || echo "K6-STEADY-FAIL"
  kill "$WATCH" 2>/dev/null; exit 1
fi
aborted && { echo "PHASE-B-ABORT (watchdog fired during steady soak)"; kill "$WATCH" 2>/dev/null; exit 1; }
cp "$RUN/k6-summary.json" "$RUN/faults/k6-summary-steady.json" 2>/dev/null
# Steady-soak gate (fault windows are NOT gated - elevated errors are the observation):
# failed_rate (col 5) <= 1% during steady state, scrub witness (col 6) zero.
[ -s "$RUN/k6-line.csv" ] || { echo "K6-STEADY-FAIL: empty k6-line.csv"; kill "$WATCH" 2>/dev/null; exit 1; }
FAILED=$(awk -F, 'END{print $5}' "$RUN/k6-line.csv")
SCRUB=$(awk -F, 'END{print $6}' "$RUN/k6-line.csv")
[ -n "$FAILED" ] && [ -n "$SCRUB" ] || { echo "K6-STEADY-FAIL: k6-line.csv cols empty (failed='$FAILED' scrub='$SCRUB')"; kill "$WATCH" 2>/dev/null; exit 1; }
awk -v f="$FAILED" 'BEGIN{exit !(f+0<=0.01)}' || { echo "K6-STEADY-FAIL: error rate $FAILED > 1%"; kill "$WATCH" 2>/dev/null; exit 1; }
[ "$SCRUB" = "0" ] || { echo "K6-STEADY-FAIL: scrub witness sum $SCRUB"; kill "$WATCH" 2>/dev/null; exit 1; }
echo "K6-STEADY-DONE failed=$FAILED scrub=$SCRUB"

run_fault() { # run_fault <label> <lever>
  local label="$1" lever="$2"
  aborted && return 1
  echo "FAULT-$label-SET"
  bash "$HERE/scripts/faults.sh" "$lever" set 2>&1 | tee -a "$RUN/faults/fault-log.txt" \
    || { echo "FAULT-$label-FAIL set"; return 1; }
  jreset
  k6_window "$label-window" || { aborted && echo "FAULT-$label-FAIL window (watchdog abort)"; echo "FAULT-$label-FAIL window"; return 1; }
  jsave "$label-window"
  echo "FAULT-$label-WINDOW-DONE"
  bash "$HERE/scripts/faults.sh" "$lever" clear 2>&1 | tee -a "$RUN/faults/fault-log.txt" \
    || { echo "FAULT-$label-FAIL clear"; return 1; }
  echo "FAULT-$label-CLEARED"
  jreset
  k6_window "$label-recovery" || { aborted && echo "FAULT-$label-FAIL recovery (watchdog abort)"; echo "FAULT-$label-FAIL recovery"; return 1; }
  jsave "$label-recovery"
  echo "FAULT-$label-RECOVERED"
  aborted && { echo "FAULT-$label-FAIL (watchdog abort)"; return 1; }
  # slice the host log set..recovery (12m upper bound) so the scan covers this fault's window
  docker compose logs --no-color --since 12m soakhost > "$RUN/faults/host-$label.log" 2>/dev/null
  bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "FAULT-$label-FAIL secret-scan"; return 1; }
  echo "FAULT-$label-SCAN-ZERO"
  echo "FAULT-$label-DONE"
}

# paired iteration (label lever)
set -- 1a idp-slow 1b idp-down 2 vendor-429 3 vendor-5xx 4 reset-mid 5 reload-mix 6 rotate 7 clock-skew 8 slowloris
while [ $# -gt 0 ]; do
  run_fault "$1" "$2" || { echo "PHASE-B-ABORT at fault $1"; kill "$WATCH" 2>/dev/null; exit 1; }
  shift 2
done

mkdir -p "$RUN/logs"
docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
aborted && { echo "PHASE-B-ABORT (watchdog fired before final scan)"; kill "$WATCH" 2>/dev/null; exit 1; }
bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "FINAL-SCAN-FAILED"; kill "$WATCH" 2>/dev/null; exit 1; }
echo "FINAL-SCAN-ZERO"
kill "$WATCH" 2>/dev/null
echo "PHASE-B-DONE dir=$RUN"
