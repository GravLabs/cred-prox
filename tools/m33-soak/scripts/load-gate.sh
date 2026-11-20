#!/usr/bin/env bash
# M33 load gate — a green marker must assert the workload's EFFECT (plan §5.5).
# Usage: load-gate.sh <run-dir>
# The 2026-11-19 13:53Z run proved the old gate blind: every request was a 401 refusal
# and LOAD-GATE-OK printed anyway, because http_req_failed is transport-only in k6 1.x
# (a connection-refused GET keeps {passes:3, fails:0, rate:1}) and scrub_miss cannot
# miss what never reached a body. This gate fails unless ALL of:
#  1. k6 `checks` (literal per-request status 200): fails == 0, passes == iterations > 0.
#  2. SoakHost log: zero transform-set 4xx/5 refusals, caller-auth failure line count
#     within its budget (see term 2's note).
#  2b. SoakHost log CUMULATIVE: count of 'Proxying to' lines == k6 iterations exactly —
#      every iteration was proxied, and the host log was not silent (added after the
#      2026-11-19 4 h run's end-of-run derivation; the driver gate at that run carried
#      no host-side equality term, so whole-run coverage needed this derivation).
#  2c. SoakHost log CUMULATIVE: a positive count of vendor-side IdP token POSTs and
#      login-exchange POSTs through the proxy (whole-run witness; the WireMock journal
#      is a newest-kept RING and cannot speak for the earlier part of a 4 h run).
#  3. WireMock journal (LAST WINDOW): every scenario's proxied path seen (cc, gen1,
#     login, sse) and at least one IdP token call — the proxied route is witnessed, not assumed.
#  4. scrub_miss sum == 0.
# Prints LOAD-GATE-OK with every number inline, or LOAD-GATE-RED with each failed term.
# Exit 0 / 1. Replayable against any finished run dir (e.g. for a RED witness).
set -u
RUN="${1:?usage: load-gate.sh <run-dir>}"
SUM="$RUN/k6-summary.json"
LOG="$RUN/logs/soakhost.log"
JOURNAL="$RUN/journal/wiremock.json"
[ -f "$SUM" ] || { echo "LOAD-GATE-RED reason=missing $SUM"; exit 1; }
[ -f "$LOG" ] || { echo "LOAD-GATE-RED reason=missing $LOG"; exit 1; }
[ -f "$JOURNAL" ] || { echo "LOAD-GATE-RED reason=missing $JOURNAL"; exit 1; }

RED=""

# --- term 1: checks vs iterations (the counter that caught the all-401 run)
read -r CP CF IT <<<"$(python3 -I -c "
import json
m = json.load(open('$SUM'))['metrics']
c = m.get('checks', {}).get('values', {})
it = m.get('iterations', m.get('http_reqs', {})).get('values', {}).get('count', 0)
print(c.get('passes', 0), c.get('fails', 0), it)
")"
# --- scrub witness comes from the CSV handleSummary ALWAYS writes: a k6 counter that
# never fires is absent from the summary JSON entirely, so the summary is not a valid
# zero-source for it. The line must also carry the two checks cols (old 6-col shape is
# the pre-fix format and cannot be gated on).
CSV="$RUN/k6-line.csv"
[ -f "$CSV" ] || { echo "LOAD-GATE-RED reason=missing $CSV"; exit 1; }
read -r CSVOK SCRUB <<<"$(awk -F, 'END{print ((NF>=8 && $6!="") ? "ok" : "bad"), $6}' "$CSV")"
[ "${CSVOK:-bad}" = "ok" ] || RED="$RED csv_incomplete_or_old_format"
[ "${SCRUB:-x}" = "0" ] || RED="$RED scrub_miss=$SCRUB"
[ "${IT:-0}" -gt 0 ] || RED="$RED iterations=0"
[ "${CF:-0}" -eq 0 ] || RED="$RED checks_fails=$CF"
[ "${CP:-0}" -eq "${IT:-0}" ] || RED="$RED checks_passes=$CP!=iterations=$IT"

# --- term 2: host-side refusals must be zero (no pipefail; grep -c prints 0 on no-match).
# The caller-auth info line also fires for the login-exchange POST, which is anonymous by
# design (the exchange call presents no caller key); every such call logs exactly one line.
# So the auth-line budget is one per journaled login call — any protected route that lost
# its key would instead surface as a transform-set 401 and fail the refusals term above.
REFUSALS=$(grep -cE 'Not Proxying, a [45][0-9][0-9] response was set by the transforms' "$LOG")
NOTAUTH=$(grep -c 'was not authenticated' "$LOG")
[ "$REFUSALS" -eq 0 ] || RED="$RED host_transform_refusals=$REFUSALS"
# --- terms 2b/2c: cumulative host-log witnesses over the WHOLE run (the journal below is
# a newest-kept ring: at ~67 vendor req/s the 30k cap covers only the last ~7.5 min, so
# near-zero idp/login journal lines at a 4 h end can be legitimate with cached tokens —
# triage against these cumulative counts, never against a re-labeled journal value).
# 2b doubles as the log-non-silent assert: a log-level or wording drift collapses
# PROXY_TOTAL while k6's own checks stay green, and equality then goes red first.
# Measured on the 4 h 2026-11-19 run: PROXY_TOTAL 993599 == iterations 993599, buckets
# cc+gen1-bucket+sse summing to exactly that; mints 480 (one per 30 s refresh) and
# exchanges 160 (one per 90 s) — cache absorbs, the void 13:53Z run would print 0/0.
PROXY_TOTAL=$(grep -c 'Proxying to' "$LOG")
[ "$PROXY_TOTAL" -eq "$IT" ] || RED="$RED host_proxy_total=$PROXY_TOTAL!=iterations=$IT"
MINTS=$(grep -c 'Start processing HTTP request POST http://toxiproxy:8003/idp/token' "$LOG")
EXCHANGES=$(grep -c 'Start processing HTTP request POST http://toxiproxy:8003/login/prod/login' "$LOG")
[ "$MINTS" -gt 0 ] || RED="$RED host_idp_mints=$MINTS"
[ "$EXCHANGES" -gt 0 ] || RED="$RED host_login_exchanges=$EXCHANGES"

# --- term 3: the journal must show the proxied path actually ran, per scenario.
# The real /__admin/requests dump keys requests by 'url' WITH query string (verified on the
# 2026-11-19 18:59Z smoke journal); older fixtures used 'path'. Accept both, strip the query.
JOUR=$(python3 -I -c "
import json
from collections import Counter
reqs = json.load(open('$JOURNAL')).get('requests', [])
def p_of(r):
    rq = r.get('request', {})
    p = rq.get('path') or rq.get('url', '')
    return p.split('?', 1)[0]
paths = Counter(p_of(r) for r in reqs)
want = {'/cc/echo': 0, '/gen1/echo': 0, '/login/prod/login': 0, '/sse/stream': 0, '/idp/token': 0}
for p in paths:
    if p in want:
        want[p] = paths[p]
print(' '.join(f'{p.split(chr(47))[1]}={want[p]}' for p in want))
")
LOGIN_CALLS=$(echo "$JOUR" | tr ' ' '\n' | sed -n 's/^login=//p')
LOGIN_CALLS="${LOGIN_CALLS:-0}"
[ "$LOGIN_CALLS" -gt 0 ] || RED="$RED journal_login=$LOGIN_CALLS"
[ "$NOTAUTH" -le "$LOGIN_CALLS" ] || RED="$RED host_caller_auth_failures=$NOTAUTH>login_calls=$LOGIN_CALLS"
for pair in $JOUR; do
  case "$pair" in login=*) continue ;; esac
  n="${pair#*=}"
  [ "$n" -gt 0 ] || RED="$RED journal_${pair}"
done

if [ -n "$RED" ]; then
  echo "LOAD-GATE-RED$RED journal[$JOUR] checks_pass=$CP checks_fail=$CF iterations=$IT scrub=$SCRUB"
  exit 1
fi
# Every number on the OK line is the MEASURED value — a marker must never print a
# constant 0 for a term it computed (the 2026-11-19 boot-window NOTAUTH lines stayed
# inside the login-call budget, and the printed line must show that openly: here 2).
echo "LOAD-GATE-OK checks_pass=$CP/$IT host_refusals=$REFUSALS caller_auth_failures=$NOTAUTH host_proxy_total=$PROXY_TOTAL host_mints=$MINTS host_exchanges=$EXCHANGES journal[$JOUR] scrub=$SCRUB"
