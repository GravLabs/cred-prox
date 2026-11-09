#!/usr/bin/env bash
# Fault lever per plan §5.5 - one subcommand per lever, `set` before the run window and
# `clear` after; each prints the PRE-STATED expectation it will be judged against.
# Recovery measurement = k6 error rate back to baseline + stats.csv socket count back to
# the warm-up band (both read from the run dir, not from this script).
set -u
TOXI=http://127.0.0.1:8474
WM=http://127.0.0.1:18081
RUN="${SOAK_RUN_DIR:?set SOAK_RUN_DIR to the run dir}"
ACTION="${2:-}"

expect() { echo "EXPECTATION: $1"; }

MAP="$(cd "$(dirname "$0")/../wiremock/mappings" && pwd)"
# Stub-swap lever. Attempt #2 triage: WireMock 3.9.2 has NO scenario-force endpoint -
# POST /__admin/scenarios answers 404 and forced state cannot be PUT back (only states
# inside possibleStates are accepted, Started/normal are not) - so every scenario-gated
# fault silently no-op'd (journal 100% 200s). Flip = POST a priority-override copy of the
# mapping file; clear = DELETE by the persisted id. Sabotage-probed live on 3.9.2:
# 429+Retry-After<->200, 500, skew expires_in -30<->positive, kv2<->kv1 bodies deep-equal.
flipstub() { # flipstub <mapping-file-stem>
  local stem="$1" body id
  body="$(python3 -I -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('scenarioName','requiredScenarioState','newScenarioState'): d.pop(k,None)
d['priority']=0
d['name']='swap-'+sys.argv[2]
print(json.dumps(d))" "$MAP/$stem.json" "$stem")" || return 1
  id="$(curl -fsS -X POST "$WM/__admin/mappings" -H 'Content-Type: application/json' -d "$body" \
        | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')" || return 1
  echo "$id" > "$RUN/faults/.stub-$stem.id"
  echo "swap-on $stem id=${id:0:8}"
}
dropstub() { # dropstub <mapping-file-stem>
  local stem="$1"
  local idf="$RUN/faults/.stub-$stem.id"
  [ -s "$idf" ] || { echo "swap-off $stem FAILED: no persisted stub id"; return 1; }
  curl -fsS -X DELETE "$WM/__admin/mappings/$(cat "$idf")" >/dev/null || return 1
  rm -f "$idf"; echo "swap-off $stem"
}
toxic() { # toxic <proxy> <name> <type> <json-attrs>
  curl -fsS -X POST "$TOXI/proxies/$1/toxics" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"type\":\"$3\",\"attributes\":$4,\"toxicity\":1.0}" >/dev/null
  echo "toxic $2 on $1"
}
untoxic() { curl -fsS -X DELETE "$TOXI/proxies/$1/toxics/$2" >/dev/null; echo "toxic $2 off $1"; }

case "$1" in
  idp-slow)
    [ "$ACTION" = set ] && { expect "fault 1: single-flight holds (one /idp/token per key per window); documented 502 shape on exhaustion"; toxic idp lat latency '{"latency":900,"jitter":100}'; } || untoxic idp lat ;;
  idp-down)
    [ "$ACTION" = set ] && { expect "fault 1: callers get credential_unavailable 502; at recovery <=2 token requests per key (no herd)"; toxic idp dead reset_peer '{"timeout":0}'; } || untoxic idp dead ;;
  vendor-429)
    if [ "$ACTION" = set ]; then
      expect "fault 2: cluster pauses ~= Retry-After 5s (+/-1s) then lifts; no silent retries in the journal"; flipstub vendor_429
    else dropstub vendor_429; fi ;;
  vendor-5xx)
    if [ "$ACTION" = set ]; then
      expect "fault 3: breaker opens at 50% failure ratio -> 503; half-open probes exactly at configured count; closes after successes"; flipstub vendor_5xx
    else dropstub vendor_5xx; fi ;;
  reset-mid)
    [ "$ACTION" = set ] && { expect "fault 4: clean failures within attempt timeout, no hang; sockets back to baseline <=60s after clear"; toxic vendor tmo timeout '{"timeout":250}'; } || untoxic vendor tmo ;;
  clock-skew)
    if [ "$ACTION" = set ]; then
      expect "fault 7: near/past-expiry tokens refresh, zero 401s at vendor, refresh stays single-flight"; flipstub idp_token_skew
    else dropstub idp_token_skew; fi ;;
  rotate)
    # fault 6 (design decision): rotate the KV-backed value on the stub - the REAL provider
    # (1.3.2 AddAzureKeyVault, ReloadInterval polling, transport-swapped to this stub) must
    # pick the rotated value on its next tick. The config-rebind variant stays as the
    # secondary witness under reload-mix (file watcher).
    # B3 fix (design decision): swapping only the per-secret stub never reached the provider - it
    # polls the LIST and re-fetches a secret only when attributes.updated changes. Set order:
    # per-secret first (so the re-fetch serves kv2), then the bumped list (triggers it).
    # Clear order: per-secret first again (so the revert re-fetch serves kv1), then the list.
    if [ "$ACTION" = set ]; then
      expect "fault 6: KV rotation lands on the next ReloadInterval tick (~10s+poll jitter); minted tokens keep working to expiry; no 401 storm; stale (kv1) value stops appearing on new gen2 requests after at most 2 ticks; one per-secret GET per flip"
      flipstub kv_gen2_kv2 && flipstub kv_list_bumped
    else
      expect "fault 6 recovery: gen2 error rate back to baseline; provider journal (host log) shows one reload around the flip, no polling storm"
      dropstub kv_gen2_kv2 && dropstub kv_list_bumped
    fi ;;
  reload-mix)
    # fault 5: atomic swap of secret AND allow-list for caller-b in one file write.
    # Doubles as the secondary config-rebind witness for rotation (design decision 2026-11-08: keep cheap).
    [ "$ACTION" = set ] && {
      expect "fault 5: journal pairs (gen tag, matching secret) only - zero mixed pairs; failed rebind keeps serving"
      python3 -I - "$RUN" <<'PY'
import json, secrets, sys, pathlib
run = pathlib.Path(sys.argv[1]); p = run / "host-config" / "appsettings.json"
conf = json.loads(p.read_text())
new = "soak-mixed-" + secrets.token_hex(16)
conf["CredProx"]["Secrets"]["vendor-gen1-key"] = new
ops = conf["CredProx"]["Callers"]["caller-b"]["Operations"]
if not any(o.get("Route") == "gen2" for o in ops):
    ops.append({"Route": "gen2", "Methods": ["GET"]})
p.write_text(json.dumps(conf, indent=2))
with (run / "sentinels.txt").open("a") as f: f.write(new + "\n")
print("REBOUND gen1 secret + caller-b allow-list")
PY
    } || expect "fault 5 recovery: allow-list settled (caller-b may use gen2), no mixed pairs in journal" ;;
  slowloris)
    [ "$ACTION" = set ] && { expect "fault 8: normal callers p95 <= +20%; refused extra sockets, not thread exhaustion"; nohup python3 "$(dirname "$0")/slowloris.py" --sockets 64 --seconds 120 > "$RUN/logs/slowloris.log" 2>&1 & echo "slowloris started pid $!"; } || pkill -f slowloris.py ;;
  *) echo "usage: faults.sh {idp-slow|idp-down|vendor-429|vendor-5xx|reset-mid|clock-skew|rotate|reload-mix|slowloris} {set|clear}"; exit 2 ;;
esac
