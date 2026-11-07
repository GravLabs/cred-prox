#!/usr/bin/env bash
# E11 shortened load script (plan §6: "load script shortened"). The nightly NBomber
# suite (tests/CredProx.LoadTests) holds the rigorous rate assertions; this script
# drives the three operational behaviors against a running host + WireMock and asserts
# each one visibly. Run via ./smoke.sh, or by hand with both processes up.
set -uo pipefail

BASE=${BASE:-http://localhost:5091}
WM=${WM:-http://localhost:8091}
failed=0

ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; failed=1; }
code() { curl -s -o /dev/null -w '%{http_code}\n' "$1"; }
# WireMock 3.x admin API: count is POST-with-body, the journal clears via DELETE,
# and stub scenarios restart separately.
wm_count() { curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "$WM/__admin/requests/count" \
             | grep -o '"count" : [0-9]\+' | grep -o '[0-9]\+'; }
wm_reset() { curl -sf -X DELETE "$WM/__admin/requests" >/dev/null; curl -sf -X POST "$WM/__admin/scenarios/reset" >/dev/null; }

echo "== 1. Rate limit: 30-request burst against a 5 req/s cluster =="
wm_reset
codes=$(for _ in $(seq 1 30); do code "$BASE/limited" & done | sort | uniq -c)
c200=$(echo "$codes" | awk '$2=="200" {print $1+0}')
c429=$(echo "$codes" | awk '$2=="429" {print $1+0}')
seen=$(wm_count)
echo "  client saw: ${c200:-0}x200 ${c429:-0}x429 | vendor saw: ${seen:-?} requests"
[ "${c429:-0}" -ge 15 ] && ok "burst shed to 429 (queue full -> credprox.throttled)" \
                        || bad "expected >=15x429, got ${c429:-0}"
[ "${seen:-99}" -le 15 ] && [ "${seen:-0}" -ge 1 ] && ok "upstream never saw the burst (held near 5 req/s)" \
                         || bad "vendor saw ${seen:-?} requests - rate limit did not hold"

echo "== 2. Vendor 429 + Retry-After: the cluster pauses =="
wm_reset
r1=$(code "$BASE/vendor")
r2=$(code "$BASE/vendor")   # the vendor's own 429 (Retry-After: 2)
t0=$(date +%s%N)
r3=$(code "$BASE/vendor")   # arrives during the pause: held, not forwarded
ms=$(( ( $(date +%s%N) - t0 ) / 1000000 ))
r4=$(code "$BASE/vendor")   # after the pause the cluster flows again
echo "  r1=$r1 r2=$r2 r3=$r3 after ${ms}ms held r4=$r4"
[ "$r1" = "200" ] && [ "$r2" = "429" ] \
  && ok "the vendor's own 429 passed through untouched" \
  || bad "expected 200 then 429, got $r1 then $r2"
[ "$ms" -ge 1000 ] && ok "the next request was held for the advertised Retry-After (${ms}ms)" \
                   || bad "r3 took only ${ms}ms - the cluster did not pause"
[ "$r4" = "200" ] && ok "traffic flows again once the pause expired" \
                  || bad "expected recovery to 200, got $r4"

echo "== 3. Circuit breaker: 500s open it, 503s answer, recovery closes it =="
wm_reset
f1=$(code "$BASE/flaky"); f2=$(code "$BASE/flaky"); f3=$(code "$BASE/flaky")
f4=$(code "$BASE/flaky")   # the 4th failure meets MinimumThroughput 4: the breaker opens here
f5=$(code "$BASE/flaky"); f6=$(code "$BASE/flaky")
held=$(wm_count)
echo "  f1..f6: $f1 $f2 $f3 $f4 $f5 $f6 | vendor saw: ${held:-?} requests"
[ "$f1" = "500" ] && [ "$f2" = "500" ] && [ "$f3" = "500" ] && [ "$f4" = "500" ] \
  && ok "upstream failures passed through while the breaker stayed closed" \
  || bad "expected the first four 500s, got $f1/$f2/$f3/$f4"
[ "$f5" = "503" ] && [ "$f6" = "503" ] \
  && ok "open circuit answers 503 (credprox.upstream_unavailable)" \
  || bad "expected 503s once the circuit opened, got f5=$f5 f6=$f6"
[ "${held:-99}" -le 5 ] && [ "${held:-0}" -ge 1 ] && ok "the open circuit stopped reaching the vendor" \
                        || bad "vendor saw ${held:-?} requests - breaker let too much through"
echo "  waiting out the 3s break for the half-open probe..."
sleep 4
f7=$(code "$BASE/flaky")
[ "$f7" = "200" ] && ok "half-open probe succeeded; the circuit closed" \
                  || bad "expected recovery to 200, got $f7"

echo "== 4. Credential health =="
health=$(curl -sf "$BASE/health")
echo "  /health: $health"
[ "$health" = "Healthy" ] && ok "credprox health check is Healthy" \
                          || bad "health is '$health'"

if [ "$failed" = "0" ]; then
  echo "OPERATIONS OK: throttling held the rate, the vendor pause was honored, the breaker opened and recovered, health is green."
else
  echo "OPERATIONS FAILED"
fi
exit "$failed"
