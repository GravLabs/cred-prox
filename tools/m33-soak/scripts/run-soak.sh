#!/usr/bin/env bash
# M33 steady-soak runner (plan §5.5). Budget guards: hourly uptime check, back off (kill k6,
# tear down) if the 5-min load average passes 40. Teardown runs on EVERY exit path.
# Usage: run-soak.sh [--smoke] [--minutes N] [--vus N]
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

cleanup() {
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

(
  end=$(( $(date +%s) + (MINUTES + 10) * 60 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    sleep 3600
    load5="$(awk '{print int($1)}' /proc/loadavg)"
    echo "watchdog: 5-min load $load5"
    if [ "$load5" -gt 40 ]; then
      echo "BACKOFF: load $load5 > 40 - stopping load generator"
      docker compose stop k6 >/dev/null 2>&1
      pkill -f 'k6 run /k6/soak.js' 2>/dev/null
      exit 0
    fi
  done
) &
WATCH=$!

docker compose --profile load run --rm k6 || { echo "K6-FAIL"; kill "$WATCH" 2>/dev/null; exit 1; }
kill "$WATCH" 2>/dev/null

# Evidence BEFORE the scan (the scan reads these): the trap recollects on failure paths.
mkdir -p "$RUN/logs"
docker compose logs --no-color soakhost > "$RUN/logs/soakhost.log" 2>/dev/null
curl -fsS http://127.0.0.1:18081/__admin/requests > "$RUN/journal/wiremock.json" 2>/dev/null
bash "$HERE/scripts/secret-scan.sh" "$RUN" || { echo "RUN FAILED: secret hygiene"; exit 1; }
# Load gate: a green marker must mean the workload actually worked (smoke #5 lesson:
# upstream refused every request yet the run reported DONE). k6-line.csv cols:
# ts,med,p95,p99,failed_rate,scrub_sum from handleSummary.
[ -s "$RUN/k6-line.csv" ] || { echo "RUN FAILED: k6-line.csv empty"; exit 1; }
FAILED=$(awk -F, 'END{print $5}' "$RUN/k6-line.csv")
SCRUB=$(awk -F, 'END{print $6}' "$RUN/k6-line.csv")
# empty cols would coerce to 0 and lie green - the summary line must be complete
[ -n "$FAILED" ] && [ -n "$SCRUB" ] || { echo "RUN FAILED: k6-line.csv cols empty (failed='$FAILED' scrub='$SCRUB')"; exit 1; }
awk -v f="$FAILED" 'BEGIN{exit !(f+0<=0.01)}' || { echo "RUN FAILED: error rate $FAILED > 1%"; exit 1; }
[ "$SCRUB" = "0" ] || { echo "RUN FAILED: scrub witness sum $SCRUB"; exit 1; }
echo "LOAD-GATE-OK failed=$FAILED scrub=$SCRUB"
echo "SOAK-RUN-DONE dir=$RUN"
