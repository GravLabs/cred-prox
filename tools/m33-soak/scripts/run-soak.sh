#!/usr/bin/env bash
# M33 steady-soak runner (plan §5.5). Budget guards: load sampled every <=60 s (the
# watchdog's bounded step), back off (stop this run's label-tagged k6 one-off, tear down,
# fail the load gate by name) if the 5-min load average passes SOAK_LOAD_LIMIT.
# Teardown runs on EVERY exit path.
# Usage: run-soak.sh [--smoke] [--minutes N] [--vus N]
# Env: SOAK_LOAD_LIMIT overrides the backoff threshold (default 40; lets the backoff
# branch be witnessed on a short run without waiting for a real load spike).
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
MINUTES=240; VUS=20
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) MINUTES=3; VUS=4 ;;
    --minutes) MINUTES="$2"; shift ;;
    --vus) VUS="$2"; shift ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done

RUN="/tmp/m33-soak-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN/journal"; touch "$RUN/stats.csv" "$RUN/k6-line.csv"
# the k6 container's user must be able to create the summary and append the CSV line
chmod 777 "$RUN"; chmod 666 "$RUN/k6-line.csv" "$RUN/stats.csv"
"$HERE/scripts/init-secrets.sh" "$RUN" || { echo "INIT-FAIL"; exit 1; }
export SOAK_RUN_DIR="$RUN" SOAK_VUS="$VUS" SOAK_MINUTES="$MINUTES"
cd "$HERE/compose" || exit 2

WATCH=""
cleanup() {
  # stop the watchdog FIRST: the loop alone was harmless, its sleep held stdout
  [ -n "$WATCH" ] && kill "$WATCH" 2>/dev/null
  docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
  curl -fsS http://127.0.0.1:18081/__admin/requests > "$RUN/journal/wiremock.json" 2>/dev/null
  bash "$HERE/scripts/teardown.sh"
}
trap cleanup EXIT

docker compose up -d toxiproxy wiremock soakhost || { echo "UP-FAIL"; exit 1; }
for _ in $(seq 1 60); do
  curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:18080/healthz >/dev/null || { echo "HEALTH-FAIL (see: docker compose logs soakhost)"; exit 1; }

# the step is bounded by the remaining budget (fine enough to still sample load) and the
# loop's TERM trap reaps the sleep IT started: killing only the loop orphaned the sleep,
# which held the caller's stdout pipe for up to an hour after TEARDOWN-DONE (qitem-20261120004151)
LOAD_LIMIT="${SOAK_LOAD_LIMIT:-40}"
(
  end=$(( $(date +%s) + (MINUTES + 10) * 60 ))
  s=""
  trap '[ -n "$s" ] && kill "$s" 2>/dev/null; exit 0' TERM INT HUP
  while :; do
    now=$(date +%s)
    rem=$(( end - now ))
    [ "$rem" -le 0 ] && break
    step=$(( rem < 60 ? rem : 60 ))
    sleep "$step" &
    s=$!
    wait "$s"
    s=""
    load5="$(awk '{print int($1)}' /proc/loadavg)"
    echo "watchdog: 5-min load $load5"
    if [ "$load5" -gt "$LOAD_LIMIT" ]; then
      echo "BACKOFF: load $load5 > $LOAD_LIMIT - stopping load generator"
      # `compose stop k6` never touches the `compose run --rm` one-off (it is not a
      # project service) and host pkill cannot see inside its namespace — the run kept
      # load high after BACKOFF (qitem-20261120021049). The one-off carries this run's
      # label, so stop exactly the containers this run started. Marker FIRST and stop
      # tolerant (F-4): a failed stop — empty id list (no-arg docker stop, rc=1) or an
      # already-gone container — must never preempt the marker, whatever shell options
      # this subshell runs under; a backoff without its marker grades as a normal soak.
      mkdir -p "$RUN" && touch "$RUN/backoff.fired"
      ids="$(docker ps -q --filter "label=m33-soak-run=$RUN" 2>/dev/null || true)"
      if [ -n "$ids" ]; then docker stop $ids 2>/dev/null || true; fi
      exit 0
    fi
  done
) &
WATCH=$!

# The one-off container carries this run's label so the watchdog can stop exactly it
# (see the BACKOFF branch); a backoff that fired makes the whole run a NAMED failed gate,
# checked before K6-FAIL so the real cause is the line that prints.
K6_RC=0
docker compose --profile load run --rm --label "m33-soak-run=$RUN" k6 || K6_RC=$?
kill "$WATCH" 2>/dev/null
if [ -f "$RUN/backoff.fired" ]; then
  echo "BACKOFF-GATE-FAIL: load watchdog stopped this run's k6 container (5-min load above $LOAD_LIMIT) - the load gate failed"
  exit 1
fi
[ "$K6_RC" -eq 0 ] || { echo "K6-FAIL"; exit 1; }

# Evidence BEFORE the scan (the scan reads these): the trap recollects on failure paths.
mkdir -p "$RUN/logs"
docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
curl -fsS http://127.0.0.1:18081/__admin/requests > "$RUN/journal/wiremock.json" 2>/dev/null
bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "RUN FAILED: secret hygiene"; exit 1; }
# Load gate: a green marker must mean the workload actually ran the PROXIED path
# (smoke #5 lesson: upstream refused every request yet the run reported DONE;
# 2026-11-19 lesson: a run where every request was a 401 refusal also reported
# LOAD-GATE-OK, because http_req_failed is transport-only). The gate lives in
# load-gate.sh and reads the k6 summary, the host log and the WireMock journal.
# k6-line.csv cols: ts,med,p95,p99,failed_rate,scrub_sum,checks_pass,checks_fail.
[ -s "$RUN/k6-line.csv" ] || { echo "RUN FAILED: k6-line.csv empty"; exit 1; }
# empty cols would coerce to 0 and lie green - the summary line must be complete
awk -F, 'END{exit !(NF>=8 && $5!="" && $6!="" && $7!="" && $8!="")}' "$RUN/k6-line.csv" \
  || { echo "RUN FAILED: k6-line.csv cols incomplete"; exit 1; }
bash "$HERE/scripts/load-gate.sh" "$RUN" || exit 1
echo "SOAK-RUN-DONE dir=$RUN"
