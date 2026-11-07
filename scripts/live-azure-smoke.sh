#!/usr/bin/env bash
# M26 live Azure/Entra validation battery (docs/azure-live-test-plan.md).
#
# Runs the phase smokes against the person's REAL tenant/subscription and
# prints PASS/FAIL/SKIP evidence lines. Safe to commit: this file carries
# resource NAMES and env-var KEYS only — never a secret value, never a
# tenant/subscription GUID.
#
# SKIP semantics (CI parity): with no az sign-in the whole battery SKIPs and
# exits 0, so the script can sit next to smoke.sh scripts in CI unchanged.
# Phases whose preconditions (app registrations, env-provided secret) are
# absent SKIP individually.
#
# Prerequisites (person-present setup, see the plan's ground rules):
#   az login                                        (Phase 1)
#   CREDPROX_LIVE_CLIENT_ID / CREDPROX_LIVE_CLIENT_SECRET
#     from the credprox-e5-oauth app registration, its SP Reader on the
#     credprox-live-test resource group                      (Phase 2; when
#     unset, phase 2 falls back to the e5-oauth lookup + a vault fetch)
#   credprox-live-kv vault + CREDPROX_LIVE_CLIENT_SECRET again
#     (Phase 4 WRITES the vault - owner-word scope; only run it deliberately)
#
# Phase 3 (Entra OBO) was dropped by the owner 2026-11-03 - OBO is removed
# from the library in M27; the e14 tenant objects were deleted the same day.
#
# Usage: scripts/live-azure-smoke.sh [1|2|4|5..10 ...]   (default: all)
# Phases 5-10 are round 2 (M29, plan §Round 2): they need the containerapp CLI
# extension and the deployed credprox-m29-app + credprox-m29-battery job; each
# prints SKIP (exit 0) when either is absent, so the whole battery stays CI-safe
# on a signed-in host without the round-2 infra.
set -uo pipefail
cd "$(dirname "$0")/.."

RG=credprox-live-test
PROXY_PORT=5085   # the sample pins Program.cs UseUrls; keep in sync
ARM=https://management.azure.com
PROXY_PROJECT=""  # start_proxy target (default: samples/MicrosoftGraph)
EVIDENCE=()
FAILED=0

say() { echo "  $*"; }
note() { echo; echo "== $* =="; }

signed_in() { az account get-access-token -o none >/dev/null 2>&1; }

proxy_pid=""
PROXY_SECRET=""   # when set, passed to the proxy via env (the config key
                  # CredProx:Secrets:graph-client-secret contains dashes - not a
                  # valid bash identifier, so `export` silently fails on it;
                  # `env NAME=value cmd` is the one clean channel)
PROXY_SECRET_KEY="CredProx__Secrets__graph-client-secret"   # the E5 sample's secret ref name
start_proxy() { # $1 = extra dotnet-run args (e.g. "--variant identity")
  if ! dotnet build "${PROXY_PROJECT:-samples/MicrosoftGraph}" -c Release -v q --nologo >/dev/null; then
    say "build FAILED"
    EVIDENCE+=("proxy build FAILED (see console)")
    FAILED=1
    return 1
  fi
  local secret_env=()
  [[ -n "$PROXY_SECRET" ]] && secret_env=("$PROXY_SECRET_KEY=$PROXY_SECRET")
  env "${secret_env[@]}" dotnet run --project "${PROXY_PROJECT:-samples/MicrosoftGraph}" -c Release --no-build -- ${1:-} &
  proxy_pid=$!
  for _ in $(seq 1 40); do
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
      say "proxy exited before serving"
      EVIDENCE+=("proxy exited before serving (startup refused - check config set)")
      FAILED=1
      return 1
    fi
    curl -s -o /dev/null "http://127.0.0.1:$PROXY_PORT/graph-nope" 2>/dev/null && break
    sleep 0.5
  done
}
stop_proxy() { [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null; proxy_pid=""; }
# Scratch responses (subscription lists, negative bodies) are removed on exit -
# the report's hygiene claim depends on this (adversarial pass 2026-11-04).
_scratch=(/tmp/credprox-live-sub.json /tmp/credprox-live-neg.json
          /tmp/credprox-live-neg.h /tmp/credprox-live-p4neg.json
          /tmp/credprox-live-p4neg.h)
# -r: _scratch may hold temp DIRECTORIES (e.g. the P10 rotation dir from
# mktemp -d) - plain rm -f left it behind in the first live smoke (2026-11-06).
trap 'stop_proxy; rm -rf "${_scratch[@]}"' EXIT

probe_arm() { # proxied ARM read: any signed-in user can list subscriptions
  curl -fsS -o /tmp/credprox-live-sub.json -w '%{http_code}' \
    "http://127.0.0.1:$PROXY_PORT/graph/subscriptions?api-version=2022-12-01"
}

phase1() {
  note "Phase 1: secretless TokenCredential -> real ARM (no secret anywhere)"
  export CredProx__Destinations__graph__Template="$ARM"
  export ReverseProxy__Clusters__graph__Destinations__graph__Address="$ARM/"
  export CredProx__Credentials__graph__Scope="$ARM/.default"
  start_proxy "--variant identity" || return 1
  local code
  code=$(probe_arm)
  local code2
  code2=$(probe_arm)
  if [[ "$code" == 200 && "$code2" == 200 ]] && grep -q '"subscriptionId"' /tmp/credprox-live-sub.json; then
    EVIDENCE+=("P1 proxied GET /subscriptions -> $code, repeat -> $code2, JSON body confirmed; scope $ARM/.default; no client secret in the config set")
    say "PASS: two proxied 200s with a real subscription list through CredProx"
  else
    EVIDENCE+=("P1 proxied GET /subscriptions -> $code, repeat -> $code2")
    say "FAIL: expected 200 + subscriptionId in body (got $code / $code2)"
    FAILED=1
  fi
  stop_proxy
}

phase2() {
  note "Phase 2: Entra client-credentials -> real ARM, live scrub assertions"
  # Phase 5 cycle fallback: after an infra recreate the secret lives only in the
  # vault, so pull both inputs through the az CLI identity - client id via the
  # e5-oauth lookup, secret via vault show. Scoped to LOCAL variables on purpose
  # (cycle run 2026-11-04): writing CREDPROX_LIVE_* globals would leak the value
  # into phase4's E-vs-V mode choice. Never printed, never on disk.
  local CID="${CREDPROX_LIVE_CLIENT_ID:-}" SEC="${CREDPROX_LIVE_CLIENT_SECRET:-}"
  [[ -n "$CID" ]] || CID=$(az ad app list --display-name credprox-e5-oauth --query "[0].appId" -o tsv 2>/dev/null || true)
  [[ -n "$SEC" ]] || SEC=$(az keyvault secret show --vault-name credprox-live-kv --name CredProx--Secrets--graph-client-secret --query value -o tsv 2>/dev/null || true)
  if [[ -z "$CID" || -z "$SEC" ]]; then
    EVIDENCE+=("P2 SKIP: no client id/secret (env unset; e5-oauth lookup and vault fetch both empty)")
    say "SKIP: no client id/secret reachable (env, e5-oauth lookup, or vault)"
    return 0
  fi
  local tenant
  tenant=$(az account get-access-token --query tenant -o tsv)
  export CredProx__Destinations__graph__Template="$ARM"
  export ReverseProxy__Clusters__graph__Destinations__graph__Address="$ARM/"
  export CredProx__Credentials__graph__Scope="$ARM/.default"
  export CredProx__Credentials__graph__TokenEndpoint="https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
  export CredProx__Credentials__graph__ClientId="$CID"
  # Positive run: real secret via the env channel (see PROXY_SECRET note).
  PROXY_SECRET="$SEC"
  start_proxy || return 1
  local code
  code=$(probe_arm)
  stop_proxy
  [[ "$code" == 200 ]] && say "PASS: client-credentials token minted by real Entra, proxied ARM 200"
  # Negative probe: a FRESH proxy with a wrong secret must fail, and the
  # caller-visible body must carry no secret material (the running proxy never
  # re-reads env - restarting is the only honest way to change the secret).
  PROXY_SECRET="wrong-secret-padded-nope-0000"
  start_proxy || return 1
  local negbody negcode negtype
  negcode=$(curl -s -o /tmp/credprox-live-neg.json -D /tmp/credprox-live-neg.h -w '%{http_code}' \
    "http://127.0.0.1:$PROXY_PORT/graph/subscriptions?api-version=2022-12-01")
  negtype=$(grep -im1 '^content-type' /tmp/credprox-live-neg.h | tr -d '\r' || true)
  negbody=$(cat /tmp/credprox-live-neg.json 2>/dev/null || true)
  stop_proxy
  if [[ "$code" == 200 && "$negcode" != 200 && "$negcode" != 000 ]] && ! grep -qF "${SEC:0:6}" <<<"$negbody"; then
    EVIDENCE+=("P2 live mint + proxied 200; wrong-secret restart -> $negcode ($negtype), no secret prefix in caller-visible body")
    say "PASS: wrong secret refused on a fresh run; caller-visible body carries no secret material"
  else
    EVIDENCE+=("P2 code=$code negcode=$negcode")
    say "FAIL: live mint/refusal/scrub expectations not met"
    FAILED=1
  fi
}

phase4() {
  note "Phase 4: Key Vault as the only secret source (E5 KeyVault:Uri + overwrite rotation)"
  if ! az keyvault show -n credprox-live-kv -g "$RG" -o none 2>/dev/null; then
    EVIDENCE+=("P4 SKIP: credprox-live-kv not present (create person-present per plan)")
    say "SKIP: vault credprox-live-kv absent"
    return 0
  fi
  local KVNAME=CredProx--Secrets--graph-client-secret
  # Client id is not secret: env override or the app-registration lookup.
  local CID="${CREDPROX_LIVE_CLIENT_ID:-}"
  [[ -z "$CID" ]] && CID=$(az ad app list --display-name credprox-e5-oauth --query "[0].appId" -o tsv 2>/dev/null || true)
  [[ -z "$CID" ]] && { EVIDENCE+=("P4 SKIP: client id unavailable (env or credprox-e5-oauth lookup)"); say "SKIP: client id unavailable"; return 0; }
  # Correct-value seed has two modes: E = env channel; V = the vault already holds the
  # value (owner piped `az ad app credential reset --append` straight into
  # `az keyvault secret set` - value never shown, never on disk). No UAI needed;
  # the vault provider reads run as the az CLI identity.
  local MODE=V
  [[ -n "${CREDPROX_LIVE_CLIENT_SECRET:-}" ]] && MODE=E
  if [[ "$MODE" == V ]] && ! az keyvault secret show --vault-name credprox-live-kv --name "$KVNAME" -o none 2>/dev/null; then
    EVIDENCE+=("P4 SKIP: vault secret absent and CREDPROX_LIVE_CLIENT_SECRET unset (seed person-present: env channel or owner reset-pipe)")
    say "SKIP: vault secret absent and no env secret (person-present seed required)"
    return 0
  fi
  local tenant
  tenant=$(az account get-access-token --query tenant -o tsv)
  export CredProx__Destinations__graph__Template="$ARM"
  export ReverseProxy__Clusters__graph__Destinations__graph__Address="$ARM/"
  export CredProx__Credentials__graph__Scope="$ARM/.default"
  export CredProx__Credentials__graph__TokenEndpoint="https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
  export CredProx__Credentials__graph__ClientId="$CID"
  export KeyVault__Uri="https://credprox-live-kv.vault.azure.net/"
  # NO PROXY_SECRET here: the only secret channel into the process is the vault.

  # 1. E mode: seed the vault from the env channel (owner-word scope; OVERWRITE
  # semantics). The value enters az through a pipe (--file on a process
  # substitution), never as a --value argument: argv is readable via
  # /proc/*/cmdline while the process lives (finding 2026-11-04).
  if [[ "$MODE" == E ]]; then
    if ! az keyvault secret set --vault-name credprox-live-kv --name "$KVNAME" \
         --file <(printf '%s' "$CREDPROX_LIVE_CLIENT_SECRET") -o none; then
      EVIDENCE+=("P4 FAIL: vault seed refused"); say "FAIL: vault seed"; FAILED=1; return 1
    fi
  fi
  # Version handle for the restore: the current (correct) version's id - an id, not a secret.
  local PREVID
  PREVID=$(az keyvault secret show --vault-name credprox-live-kv --name "$KVNAME" --query id -o tsv)
  # 2. Vault-only start must broker a live token.
  start_proxy || return 1
  local c1; c1=$(probe_arm); stop_proxy
  [[ "$c1" == 200 ]] && say "PASS: vault-sourced secret, proxied ARM 200 (no secret on disk or in the passed env)"
  # 3. Rotation by OVERWRITE: wrong value -> fresh start -> clean failure.
  # Crash window (adversarial pass 2026-11-04): if the run dies between here
  # and the version-pipe restore, the vault's CURRENT version holds the wrong
  # value - the previous correct version is still in the vault's history
  # (set = new version, never in-place). Recovery without the battery:
  #   az keyvault secret set --vault-name credprox-live-kv --name <KVNAME> \
  #     --file <(az keyvault secret show --id <older-ver> --query value -o tsv | tr -d '\n')
  az keyvault secret set --vault-name credprox-live-kv --name "$KVNAME" \
    --value "wrong-secret-padded-nope-0000" -o none || { EVIDENCE+=("P4 FAIL: wrong-value overwrite"); FAILED=1; return 1; }
  start_proxy || return 1
  local c2 t2 b2
  c2=$(curl -s -o /tmp/credprox-live-p4neg.json -D /tmp/credprox-live-p4neg.h -w '%{http_code}' \
    "http://127.0.0.1:$PROXY_PORT/graph/subscriptions?api-version=2022-12-01")
  t2=$(grep -im1 '^content-type' /tmp/credprox-live-p4neg.h | tr -d '\r' || true)
  b2=$(cat /tmp/credprox-live-p4neg.json 2>/dev/null || true)
  stop_proxy
  # Echo check: E mode can grep the real value's first 6 chars; V mode never holds
  # the value, so its scrub claim is honestly scoped to the problem+json shape.
  local echo_ok=0 echo_note
  if [[ "$MODE" == E ]]; then
    ! grep -qF "${CREDPROX_LIVE_CLIENT_SECRET:0:6}" <<<"$b2" && echo_ok=1
    echo_note="no secret echo in caller-visible body"
  else
    echo_ok=1
    echo_note="value unknown to the battery (V mode): echo check scoped to problem+json shape"
  fi
  # 4. Restore the correct value by VERSION PIPE: the previous version's value travels
  # through a bash FIFO into the new version - never printed, never in argv, never on
  # disk (az --file reads the pipe; tr strips tsv's trailing newline).
  az keyvault secret set --vault-name credprox-live-kv --name "$KVNAME" \
    --file <(az keyvault secret show --id "$PREVID" --query value -o tsv | tr -d '\n') -o none \
    || { EVIDENCE+=("P4 FAIL: version-pipe restore"); FAILED=1; return 1; }
  start_proxy || return 1
  local c3; c3=$(probe_arm); stop_proxy
  if [[ "$c1" == 200 && "$c2" != 200 && "$c2" != 000 ]] \
     && [[ "$echo_ok" == 1 && "$c3" == 200 ]]; then
    EVIDENCE+=("P4 mode=$MODE vault-only start -> $c1; overwrite(wrong) -> restart -> $c2 ($t2; $echo_note); version-pipe restore -> restart -> $c3 - rotation by OVERWRITE, vault left holding the correct value")
    say "PASS: overwrite rotation proven (clean failure -> recovery); secret entered the process only from the vault"
  else
    EVIDENCE+=("P4 c1=$c1 c2=$c2 c3=$c3 echo_ok=$echo_ok (expected 200 / non-200 / 200 / 1)")
    say "FAIL: vault-only / overwrite-failure / recovery expectations not met"
    FAILED=1
  fi
}

# ---- Round 2 (M29): the inside-Azure battery, phases 5-10 -----------------
# G2 model: every check runs IN-CLUSTER as the Manual Container Apps Job
# credprox-m29-battery (same image, same UAI) against the app's INTERNAL
# ingress FQDN - `az containerapp exec` is an interactive SSH-like shell and
# cannot be driven unattended, so each phase STARTS a job execution, waits for
# a terminal status, and parses the battery's machine-readable summary lines
# ("P5 PASS" / "P5 FAIL ...") from the container logs. Zero public listeners
# either way. One `--phase all` run feeds P5-P9; P10 drives single-probe
# `--phase jwtprobe` runs around a vault overwrite/restore.
# SKIP contract matches the header: unauthenticated hosts exit 0 via the
# global gate; a signed host without the CLI extension, the app, the job, or
# with unseeded material prints SKIP per phase and exits 0.
R2_APP=credprox-m29-app
R2_JOB=credprox-m29-battery
R2_VAULT=credprox-m29-kv

r2_ready() { # $1 = phase tag; returns 1 after printing + recording SKIP
  if ! az containerapp -h >/dev/null 2>&1; then
    say "SKIP: containerapp CLI extension absent (az extension add --name containerapp, per plan gate list)"; EVIDENCE+=("$1 SKIP: containerapp extension absent"); return 1
  fi
  if ! az containerapp show -n "$R2_APP" -g "$RG" -o none 2>/dev/null; then
    say "SKIP: $R2_APP not deployed (gated apply not run)"; EVIDENCE+=("$1 SKIP: $R2_APP absent"); return 1
  fi
  if ! az containerapp job show -n "$R2_JOB" -g "$RG" -o none 2>/dev/null; then
    say "SKIP: $R2_JOB not deployed (deploy-app not run to completion)"; EVIDENCE+=("$1 SKIP: $R2_JOB absent"); return 1
  fi
  return 0
}

r2_fqdn() { az containerapp show -n "$R2_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null; }

r2_run_job() { # start ONE execution with the job's current args, wait for a
               # terminal status, print the battery container log to stdout.
               # rc 1 = start failed or no terminal state within <=480s (60 x 8 s).
               # The battery exits non-zero on FAIL lines -> execution 'Failed'
               # is a RESULT to parse, not an infra error.
  local exec_name status i tries=3 rc_start=1
  # fix 13+14 (live 2026-11-06): retry ONLY a refused start (409
  # ContainerAppsJobOperationInProgress while an args PUT provisions - nonzero rc).
  # An ACCEPTED start can return rc=0 with an EMPTY properties.name while it has
  # ALREADY launched the execution - restarting on empty name duplicates runs
  # (observed: one baseline probe fired three times). On accepted-empty, resolve
  # the name from the execution list (newest) instead - never re-start.
  exec_name=""
  while (( tries > 0 )); do
    exec_name=$(az containerapp job start -g "$RG" -n "$R2_JOB" --query properties.name -o tsv 2>/dev/null); rc_start=$?
    (( rc_start == 0 )) && break
    say "job start refused (attempt $((4-tries))/3) - provisioning op likely active" >&2
    tries=$((tries-1)); (( tries > 0 )) && sleep 20
  done
  (( rc_start == 0 )) || return 1
  if [[ -z "$exec_name" ]]; then
    sleep 5
    exec_name=$(az containerapp job execution list -g "$RG" -n "$R2_JOB" \
      --query "sort_by(@,&properties.startTime)[-1].name" -o tsv 2>/dev/null)
    [[ -n "$exec_name" ]] || { say "job start accepted but execution name unresolvable" >&2; return 1; }
  fi
  status=Unknown
  for i in $(seq 1 60); do   # <=480s: cold job start + pull on Consumption can outlast 320s
    sleep 8
    status=$(az containerapp job execution show -g "$RG" -n "$R2_JOB" --job-execution-name "$exec_name" --query properties.status -o tsv 2>/dev/null) || status=Unknown
    case "$status" in Succeeded|Failed|Stopped|Timeout|Cancelled|Deleting) break ;; esac
  done
  case "$status" in
    Succeeded|Failed)
      # fix 13 (live 2026-11-06): --format text lines arrive DECORATED
      # ("<ts> stdout F P6 PASS") - strip the per-line log routing prefix so the
      # ^Pn greps actually match live output (they only matched the offline
      # battery's bare stdout; against raw live logs every line-anchored check
      # silently missed, green probes included).
      az containerapp job logs show -g "$RG" -n "$R2_JOB" --execution "$exec_name" \
        --container battery --tail 300 --format text 2>/dev/null \
        | sed -E 's/^[^ ]+ (stdout|stderr) [A-Z] //'
      return 0 ;;
    # fix 14: r2_run_job runs inside $(...) - its stdout IS the battery log, so
    # every diagnostic goes to stderr or it vanishes into the caller's $out.
    *) say "job execution $exec_name did not finish (last status: $status)" >&2; return 1 ;;
  esac
}

r2_job_args() { # rewrite the battery container's startup args via a full-document
  # PUT (fix 12, live finding 2026-11-06): the CLI's --args cannot carry values that
  # BEGIN with '--' - az parses "--mode" as its own option and dies with
  # "unrecognized arguments", and the old callers swallowed that into /dev/null,
  # so P10's retargeting silently never happened (its "jwtprobe" executions ran
  # the full battery). GET the live document, patch the args, PUT it back, then
  # READ BACK the arg count - loud on every step.
  # $1 = FQDN (proxy base, no scheme); $2 = phase ("" = full battery, "jwtprobe")
  local fq="$1" phase="${2:-}" jid rc
  jid=$(az containerapp job show -g "$RG" -n "$R2_JOB" --query id -o tsv 2>/dev/null) || return 1
  az rest --method get --uri "$jid?api-version=2024-02-02-preview" > /tmp/r2-jobargs.get.json \
    || return 1
  python3 - /tmp/r2-jobargs.get.json /tmp/r2-jobargs.put.json "$phase" "https://$fq" <<'PY' || return 1
import json, sys
get_path, put_path, phase, fq = sys.argv[1:5]
with open(get_path) as fh:
    doc = json.load(fh)
for k in ("id", "name", "type", "systemData"):
    doc.pop(k, None)
for k in ("provisioningState", "outboundIpAddresses", "eventStreamEndpoint"):
    doc.get("properties", {}).pop(k, None)
args = ["--mode", "battery", "--proxy", fq] + (["--phase", phase] if phase else [])
next(c for c in doc["properties"]["template"]["containers"] if c["name"] == "battery")["args"] = args
with open(put_path, "w") as fh:
    json.dump(doc, fh)
PY
  # fix 13 (live 2026-11-06): the PUT can hit 409 ContainerAppsJobOperationInProgress
  # while a prior provisioning operation (an earlier args PUT, or a job start) is
  # still active - retry loudly, three times, 20 s apart, then fail visibly.
  rc=1
  local tries=3
  while (( tries > 0 )); do
    if az rest --method put --uri "$jid?api-version=2024-02-02-preview" \
        --body "@/tmp/r2-jobargs.put.json" >/dev/null 2>/tmp/r2-jobargs.put.err; then rc=0; break; fi
    say "job args PUT refused (attempt $((4-tries))/3): $(head -c 160 /tmp/r2-jobargs.put.err)"
    tries=$((tries-1)); (( tries > 0 )) && sleep 20
  done
  rm -f /tmp/r2-jobargs.get.json /tmp/r2-jobargs.put.json /tmp/r2-jobargs.put.err
  [[ $rc -eq 0 ]] || return 1
  # fix 13: '--phase' + value are TWO elements: full battery = 4, with a phase = 6.
  # The want=5 here was the bug - the live read-back showed the PUT had landed the
  # CORRECT 6-element jwtprobe list while the verifier called it a mismatch.
  local want=4 n
  [[ -n "$phase" ]] && want=6
  n=$(az containerapp job show -g "$RG" -n "$R2_JOB" --query "length(properties.template.containers[0].args)" -o tsv 2>/dev/null)
  [[ "$n" == "$want" ]] || { say "FAIL: job args read-back $n, expected $want"; return 1; }
}

R2_BATT_LOG=""
R2_BATT_DONE=""
r2_battery() { # one --phase all run shared by P5-P9; rc 1 = job never finished
  [[ -n "$R2_BATT_DONE" ]] && return 0
  # defensive: a crashed P10 can leave jwtprobe args behind; normalize first
  local fq; fq=$(r2_fqdn)
  [[ -n "$fq" ]] && r2_job_args "$fq" || true
  local out
  if ! out=$(r2_run_job); then
    R2_BATT_DONE=1   # latch: one dead job fails P5-P9 without re-starting it
    return 1
  fi
  R2_BATT_LOG="$out"; R2_BATT_DONE=1
}

r2_line() { printf '%s\n' "$R2_BATT_LOG" | grep -E "^$1 (PASS|FAIL)" | head -1; }
r2_material_skip() { [[ "$R2_BATT_LOG" == *"caller key"* ]]; }

phase5() {
  note "Phase R2-P5: managed identity egress - CredProx ON a real UAI"
  r2_ready P5 || return 0
  r2_battery || { say "FAIL: battery job did not finish"; EVIDENCE+=("P5-P9 FAIL: battery job did not reach a terminal state"); FAILED=1; return 0; }
  if r2_material_skip; then say "SKIP: caller key unavailable (material not seeded)"; EVIDENCE+=("P5 SKIP: caller key absent"); return 0; fi
  local line; line=$(r2_line P5)
  if [[ "$line" == "P5 PASS"* ]]; then
    EVIDENCE+=("P5 proxied GET /subscriptions THROUGH THE UAI -> 200 + subscription list, proven IN-CLUSTER by the $R2_JOB job (first managed-identity CredProx egress); no secret anywhere")
    say "PASS: real user-assigned managed identity brokered a real ARM call"
  else
    EVIDENCE+=("P5 battery line: ${line:-MISSING} (expected P5 PASS)")
    say "FAIL: ${line:-no P5 line in battery log}"; FAILED=1
  fi
}

phase6() {
  note "Phase R2-P6: JWT assertion signed by the vault-supplied PEM key"
  r2_ready P6 || return 0
  r2_battery || { say "FAIL: battery job did not finish"; FAILED=1; return 0; }
  if r2_material_skip; then say "SKIP: caller key unavailable"; EVIDENCE+=("P6 SKIP: caller key absent"); return 0; fi
  local line; line=$(r2_line P6)
  if [[ "$line" == "P6 PASS"* ]]; then
    EVIDENCE+=("P6 /jwt -> counterparty echo assertion-verified + aud-ok: vault secret:jwt-signing-key produced a cryptographically valid RS256 client_assertion (independent verifier, same bar as GitHubApp --smoke)")
    say "PASS: vault PEM -> valid RS256 assertion end to end"
  else
    EVIDENCE+=("P6 battery line: ${line:-MISSING} (expected P6 PASS)")
    say "FAIL: ${line:-no P6 line in battery log}"; FAILED=1
  fi
}

phase7() {
  note "Phase R2-P7: HMAC request signing with the vault-supplied secret"
  r2_ready P7 || return 0
  r2_battery || { say "FAIL: battery job did not finish"; FAILED=1; return 0; }
  if r2_material_skip; then say "SKIP: caller key unavailable"; EVIDENCE+=("P7 SKIP: caller key absent"); return 0; fi
  local line; line=$(r2_line P7)
  if [[ "$line" == "P7 PASS"* ]]; then
    EVIDENCE+=("P7 /hmac -> 200, independent verifier recomputed METHOD/PATH/ts/sha256(body) with the vault secret: signature correct")
    say "PASS: vault HMAC secret signs correctly end to end"
  else
    EVIDENCE+=("P7 battery line: ${line:-MISSING} (expected P7 PASS)")
    say "FAIL: ${line:-no P7 line in battery log}"; FAILED=1
  fi
}

phase8() {
  note "Phase R2-P8: mTLS client cert loaded from the vault (encrypted PFX + password)"
  r2_ready P8 || return 0
  r2_battery || { say "FAIL: battery job did not finish"; FAILED=1; return 0; }
  if r2_material_skip; then say "SKIP: caller key unavailable"; EVIDENCE+=("P8 SKIP: caller key absent"); return 0; fi
  local line; line=$(r2_line P8)
  if [[ "$line" == "P8 PASS"* ]]; then
    EVIDENCE+=("P8 /mtls -> 200, counterparty (client-cert REQUIRED, pinned test CA) saw CN=credprox-m29-client: vault PFX+password loaded, chain verified")
    say "PASS: vault-encrypted PFX presented and verified"
  else
    EVIDENCE+=("P8 battery line: ${line:-MISSING} (expected P8 PASS)")
    say "FAIL: ${line:-no P8 line in battery log}"; FAILED=1
  fi
}

phase9() {
  note "Phase R2-P9: edge hygiene - caller key enforced; declared config holds no secrets"
  r2_ready P9 || return 0
  r2_battery || { say "FAIL: battery job did not finish"; FAILED=1; return 0; }
  if r2_material_skip; then say "SKIP: caller key unavailable"; EVIDENCE+=("P9 SKIP: caller key absent"); return 0; fi
  local line; line=$(r2_line P9)
  # host-side half: the DECLARED container env NAMES (config read-back). The
  # in-container `env` grep needed exec, which G2 removed - this half proves
  # what the app config DECLARES; the battery's own in-cluster run proves what
  # answers without a key. Wording states exactly that.
  local bad; bad=$(az containerapp show -n "$R2_APP" -g "$RG" \
    --query 'properties.template.containers[].env[].name' -o tsv 2>/dev/null \
    | grep -Ei 'credprox_live|client_secret' || true)
  if [[ "$line" == "P9 PASS"* && -z "$bad" ]]; then
    EVIDENCE+=("P9 caller-key-less request -> 401 (in-cluster, battery); DECLARED container env names carry no credential-var names (host-side read-back of the app config; secret material demonstrably arrives only from the vault)")
    say "PASS: 401 without key AND no credential env names declared"
  else
    EVIDENCE+=("P9 battery line ${line:-MISSING} (expected P9 PASS); declared-env hits: ${bad:-none}")
    say "FAIL: line=${line:-missing} env-hits=${bad:-none}"; FAILED=1
  fi
}

phase10() {
  note "Phase R2-P10: vault is the LIVE source - rotate-by-overwrite, jwtprobe job witnesses"
  r2_ready P10 || return 0
  local fq; fq=$(r2_fqdn)
  [[ -n "$fq" ]] || { say "SKIP: internal FQDN unreadable"; EVIDENCE+=("P10 SKIP: FQDN unreadable"); return 0; }
  local D; D=$(mktemp -d /tmp/credprox-m29-rot.XXXXXX)
  _scratch+=("$D")   # removed by the script's EXIT trap (round-1 hygiene rule)
  local orig="$D/orig.pem"
  # download (not `show -o tsv`): tsv would escape the PEM's real newlines and
  # the restore would push mangled bytes back into the vault.
  az keyvault secret download --vault-name "$R2_VAULT" --name 'CredProx--Secrets--jwt-signing-key' -f "$orig" 2>/dev/null || true
  if [[ ! -s "$orig" ]]; then say "SKIP: current key unreadable (material not seeded?)"; EVIDENCE+=("P10 SKIP: current jwt key unreadable"); return 0; fi

  local i out res=""
  # fix 12: thin delegates to r2_job_args (az --args cannot carry '--mode' values)
  r2_set_probe() { r2_job_args "$1" jwtprobe; }
  r2_restore_args() { r2_job_args "$1" ""; }
  # The counterparty pinned its public-key pin at STARTUP (static for the
  # phase), so a refreshed WRONG key at the proxy means signature-refusal -
  # the witness cannot self-heal mid-phase. Baseline first:
  r2_set_probe "$fq"
  out=$(r2_run_job) || { r2_restore_args "$fq"; say "FAIL: baseline probe job did not finish"; EVIDENCE+=("P10 FAIL: baseline jwtprobe job did not finish"); FAILED=1; return 0; }
  if ! printf '%s\n' "$out" | grep -qE '^P6 PASS'; then
    r2_restore_args "$fq"
    EVIDENCE+=("P10 FAIL: baseline jwtprobe not green before rotation (P6 line: $(printf '%s\n' "$out" | grep -E '^P6' | head -1 || echo none) - fix P6 first)")
    say "FAIL: baseline probe not green"; FAILED=1; return 0
  fi
  # 1) overwrite with a DIFFERENT well-formed key, keep it live until refused
  openssl genrsa -out "$D/wrong.pem" 2048 2>/dev/null
  az keyvault secret set --vault-name "$R2_VAULT" --name 'CredProx--Secrets--jwt-signing-key' --file "$D/wrong.pem" -o none
  for i in 1 2 3 4 5 6; do
    out=$(r2_run_job) || break
    printf '%s\n' "$out" | grep -qE '^P6 FAIL' && { res=wrong_refused; break; }
    sleep 20
  done
  # 2) restore the ORIGINAL on EVERY path past here (never delete+re-add -
  #    name-lock rule). If the script died before this line the vault holds
  #    the wrong key: re-running this phase restores from a fresh download
  #    after scripts/live-m29-material.sh create reseeds.
  az keyvault secret set --vault-name "$R2_VAULT" --name 'CredProx--Secrets--jwt-signing-key' --file "$orig" -o none
  r2_restore_args "$fq"
  if [[ "$res" != wrong_refused ]]; then
    EVIDENCE+=("P10 FAIL: wrong key never refused within 6 probes (refresh cadence slower than the window, or pin self-healed - check counter logs)")
    say "FAIL: rotation failure not witnessed"; FAILED=1; return 0
  fi
  # 3) recovery witness: jwtprobe runs until P6 PASSes again
  r2_set_probe "$fq"
  for i in 1 2 3 4 5 6 7 8 9; do
    out=$(r2_run_job) || break
    printf '%s\n' "$out" | grep -qE '^P6 PASS' && { res=recovered; break; }
    sleep 20
  done
  r2_restore_args "$fq"
  if [[ "$res" == recovered ]]; then
    EVIDENCE+=("P10 overwrite(wrong key) -> refusal within 6 probes; restore(original) -> recovery within 9 probes (each probe one jwtprobe job execution): the vault is the live source feeding the JWT credential (rotate-by-overwrite, vault left holding the correct value)")
    say "PASS: rotation-by-overwrite failure + recovery witnessed via job probes"
  else
    EVIDENCE+=("P10 wrong-key refusal SEEN but recovery not proven within 9 probes (vault restored by this script regardless - check P6 next run)")
    say "FAIL: recovery not witnessed"; FAILED=1
  fi
}

phases=("${@:-1 2 4}")
[[ "${1:-}" == "--all" || $# -eq 0 ]] && phases=(1 2 4 5 6 7 8 9 10)

if ! signed_in; then
  echo "live-azure-smoke: no az sign-in -> all phases SKIP (CI parity)."
  echo "evidence: P1/P2/P4-P10 SKIP (unauthenticated host)"
  exit 0
fi

for p in ${phases[*]}; do
  case "$p" in
    1) phase1 ;;
    2) phase2 ;;
    4) phase4 ;;
    5) phase5 ;;
    6) phase6 ;;
    7) phase7 ;;
    8) phase8 ;;
    9) phase9 ;;
    10) phase10 ;;
    *) echo "unknown phase: $p" >&2; exit 2 ;;
  esac
done

note "Evidence summary (copy into docs/live-validation-report.md)"
for e in "${EVIDENCE[@]}"; do say "- $e"; done
exit "$FAILED"
