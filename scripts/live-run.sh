#!/usr/bin/env bash
# One command to run a vendor's live test against the real vendor, on demand only.
# Secrets live in ONE central file (~/.config/credprox-live/live.env, mode exactly
# 600) and NEVER reach this terminal: every message names files, modes and variable
# names only. The central file holds every vendor's variables; this run reads it
# whole only into its own leak-scan map, EXPORTS ONLY ITS VENDOR's variables to its
# children, and names any stale per-vendor file as ignored without reading it. Exit codes: PASS 0, FAIL 1, SKIP-or-refused 2.
# This script is the contract for those codes; a plain `dotnet test` run of the
# project shows the same skip reasons but exits 0 on skips. A run is vendor-scoped:
# `aigateway` never executes GitHubApp's live cell and vice versa, so filling one
# vendor's file can never spend or touch the other vendor. (An aigateway run still
# starts the GitHubApp sample and its local stand-in for the offline witness and
# leak-scanner legs; that makes no GitHub traffic.)
# The graph run has a real lifecycle: scripts/live-graph-app.sh creates one Entra
# app registration (plus its service principal and one 30-day secret, held only in
# a mode-600 scratch file), the run uses it, and destroy deletes it again on every
# exit path — the destroy's read-back decides whether the run may PASS. The
# agenttokens run mirrors it with scripts/live-agenttokens-app.sh: three app
# registrations (one resource app with an api:// identifier and a docs-read app
# role, two client apps each with one secret piped straight to scratch), and the
# same create-read-back / destroy-read-back discipline. After either create the
# runner first WAITS for Entra to propagate the brand-new client secret - it
# polls the tenant's v2 token endpoint with client_credentials every 5 s (up to
# CREDPROX_M46_SECRET_WAIT_SECONDS, default 120) until a token comes back 200,
# because a cell that starts against an unpropagated secret only ever sees a 401
# the vendor cannot serve (live finding 2026-11-22). The aca run drives
# scripts/live-m46-aca.sh apply|push|deploy|verify|destroy over the whole Azure
# resource set; its live leg is the verify job's acacheck C-lines (internal
# ingress - no external test process can reach the app) and its destroy
# read-back includes the resource group being gone. Every outward step in
# this script (create, destroy, deploy) is a lead action.
set -u -o pipefail

vendor="${1:-githubapp}"
case "$vendor" in
    githubapp)
        required="APP_ID INSTALLATION_ID PRIVATE_KEY_BASE64"
        # the vendor's live + witness legs, plus the vendor-neutral scaffolding
        test_filter="FullyQualifiedName~GitHubApp|FullyQualifiedName~LiveEnvContractTests"
        ;;
    aigateway)
        required="ANTHROPIC_API_KEY"
        # the AiGateway live + offline legs, the env-contract legs, and the
        # GitHubApp offline witness and scanner legs (local stand-in only)
        test_filter="FullyQualifiedName~AiGateway|FullyQualifiedName~LiveEnvContractTests|FullyQualifiedName~GitHubAppWitnessAndScaffoldTests"
        ;;
    graph)
        required="TENANT_ID"
        # the MicrosoftGraph live cell plus its offline legs (env contract and
        # the lifecycle script's canned-az read-back cells) and the env-contract
        # legs; no other vendor's cells
        test_filter="FullyQualifiedName~MicrosoftGraph|FullyQualifiedName~GraphEnvContractTests|FullyQualifiedName~GraphAppScriptTests|FullyQualifiedName~LiveEnvContractTests"
        ;;
    agenttokens)
        required="TENANT_ID"
        # the AgentTokens live cell plus its offline legs (env contract and the
        # lifecycle script's canned-az read-back cells) and the env-contract legs
        test_filter="FullyQualifiedName~AgentTokens|FullyQualifiedName~LiveEnvContractTests"
        ;;
    aca)
        required="TENANT_ID"
        # the lifecycle script's canned-az read-back cells, the acacheck loopback
        # cell and the env-contract legs - the aca LIVE leg is the script-driven
        # leg below (internal ingress: no xunit cell can reach it; disclosed)
        test_filter="FullyQualifiedName~Aca|FullyQualifiedName~LiveEnvContractTests"
        ;;
    *)
        echo "SKIP: no live vendor '$vendor' (known vendors: githubapp, aigateway, graph, agenttokens, aca)"
        exit 2
        ;;
esac

env_file="$HOME/.config/credprox-live/live.env"
display="~/.config/credprox-live/live.env"

# Per-vendor files are dead: a stale one is named so nobody wonders whether it
# still steers the run — its values are never read, and this line never echoes them.
# Printed ABOVE the gates below on purpose: the loop stats files and reads nothing,
# so it lands even when the central file is missing (SKIP) or wrongly-moded
# (REFUSED) — a run that never starts still names the dead file it did not use.
for stale_vendor in githubapp aigateway graph agenttokens aca; do
    if [ -f "$HOME/.config/credprox-live/$stale_vendor.env" ]; then
        echo "NOTE: ~/.config/credprox-live/$stale_vendor.env exists but is IGNORED - every vendor reads $display"
    fi
done

if [ ! -f "$env_file" ]; then
    echo "SKIP: $display does not exist."
    echo "      required variables: $required"
    echo "      see docs/live-testing.md"
    exit 2
fi

mode="$(stat -c %a "$env_file")"
if [ "$mode" != "600" ]; then
    echo "REFUSED: $display is mode $mode, must be exactly 600"
    echo "         fix: chmod 600 $display"
    exit 2
fi

# The secret-propagation wait budget must be a positive whole number of seconds,
# refused here before anything is created (review LOW-2, 2026-11-22: a value such
# as "10s" made the wait's numeric comparison error out and the loop never end
# while a run-created app registration was held).
case "${CREDPROX_M46_SECRET_WAIT_SECONDS:-120}" in
    ''|*[!0-9]*|0|0*|???????*)
        echo "REFUSED: CREDPROX_M46_SECRET_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits"
        exit 2 ;;
esac

# The az vendors (Entra's graph and agenttokens, and aca's Azure resource set)
# ride the owner's az sign-in. Both gates
# below are read-only; the only writes are the create/destroy pairs further down,
# and everything they create is deleted again before this script exits — the
# destroy read-back flips the run to FAIL if anything survives.
graph_secret=""
graph_scratch="${CREDPROX_M46_SCRATCH:-/tmp/credprox-m46-graph}"
graph_app_created=0
graph_destroy_rc=0
graph_destroy() {
    # once, on every exit path after a successful create (trap EXIT)
    [ "$graph_app_created" = "1" ] || return 0
    graph_app_created=0
    echo "--- live-graph-app.sh destroy (read-back decides) ---"
    if "$repo_root/scripts/live-graph-app.sh" destroy 2>&1 | tee -a "$log"; then
        echo "graph destroy: read-back clean"
    else
        graph_destroy_rc=1
    fi
}
aca_scratch="${CREDPROX_M46_ACA_SCRATCH:-/tmp/credprox-m46-aca}"
aca_caller_key=""
aca_vendor_key=""
aca_infra_created=0
aca_destroy_rc=0
aca_destroy() {
    # once, on every exit path after apply landed the resource group (trap EXIT)
    [ "$aca_infra_created" = "1" ] || return 0
    aca_infra_created=0
    echo "--- live-m46-aca.sh destroy (read-backs decide, RG included) ---"
    if "$repo_root/scripts/live-m46-aca.sh" destroy 2>&1 | tee -a "$log"; then
        # pipefail would INVERT this branch under grep -q: grep exits at the first
        # match, tail dies on SIGPIPE (rc 141), the pipeline fails, and the clean
        # line prints on a log that DOES hold the anchor. The count reader consumes
        # the pipe to EOF. The 40-line window is sound because aca_destroy runs at
        # most once per run and nothing tees to the log after it - drop the tail
        # and count the whole log if that ever changes.
        if [ "$(tail -n 40 "$log" | grep -c 'SKIPPED: pre-group role-assignment read-back')" -gt 0 ]; then
            echo "aca destroy: resource group gone; a role-assignment check was SKIPPED (unresolved run identity - NOT a confirmed zero, see the destroy lines)"
        else
            echo "aca destroy: read-back clean (resource group gone)"
        fi
    else
        aca_destroy_rc=1
        echo "aca destroy: READ-BACK FAILED - leftovers remain; see above"
    fi
}
agenttokens_secret2=""
agenttokens_secret3=""
agenttokens_scratch="${CREDPROX_M46_SCRATCH:-/tmp/credprox-m46-agenttokens}"
agenttokens_apps_created=0
agenttokens_destroy_rc=0
agenttokens_destroy() {
    # once, on every exit path after a successful create (trap EXIT)
    [ "$agenttokens_apps_created" = "1" ] || return 0
    agenttokens_apps_created=0
    echo "--- live-agenttokens-app.sh destroy (read-back decides) ---"
    if "$repo_root/scripts/live-agenttokens-app.sh" destroy 2>&1 | tee -a "$log"; then
        echo "agenttokens destroy: read-back clean"
    else
        agenttokens_destroy_rc=1
    fi
}
declare -A loaded=()
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
        ''|'#'*) continue ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    loaded["$key"]="$value"
done < "$env_file"

missing=""
for name in $required; do
    if [ -z "${loaded[$name]:-}" ]; then
        missing="$missing $name"
    fi
done
if [ -n "$missing" ]; then
    echo "SKIP: $display is missing variables:$missing"
    exit 2
fi

# Vendor isolation: children (lifecycle scripts and the test process) receive
# ONLY this vendor's variables; the rest of the central file stays inside the
# runner's loaded map, which the leak scan below and nothing else reads.
for name in $required; do
    export "$name=${loaded[$name]}"
done

if [ "$vendor" = "graph" ] || [ "$vendor" = "agenttokens" ] || [ "$vendor" = "aca" ]; then
    if ! command -v az >/dev/null 2>&1; then
        echo "SKIP: the $vendor vendor needs the az CLI on PATH (see docs/live-testing.md)"
        exit 2
    fi
    if ! az account get-access-token >/dev/null 2>&1; then
        echo "SKIP: no active az login for the $vendor vendor (run: az login)"
        exit 2
    fi
fi

# The graph and agenttokens runs poll Entra's token endpoint to wait for a
# freshly created client secret to propagate; that needs curl before any create
# can spend anything. (The aca run has no such wait: its vault material is
# written, not minted by Entra.)
if [ "$vendor" = "graph" ] || [ "$vendor" = "agenttokens" ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "SKIP: the $vendor vendor waits for a created client secret to become usable and needs curl on PATH"
        exit 2
    fi
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$(mktemp "${TMPDIR:-/tmp}/credprox-live-run.XXXXXX.log")"
echo "log: $log"

# Leak scan over the captured log: loaded material verbatim (folded so a PEM that
# spans console line wraps still matches) and vendor token/key/JWT shapes. Names of
# hit kinds are printed; hit content never is. A failing leg (apply, push, deploy,
# verify, create) exits 1 BEFORE the inline call below is ever reached, so the
# EXIT trap calls this too - AFTER the destroys, so destroy output is scanned as
# well (finding 2026-11-22: the verify diagnostics left through an unscanned
# door). The once-guard makes the trap a no-op when the inline call already ran.
# DEFINED HERE, before the trap arms: a leg that fails early exits before any
# later line parses, so a definition at the inline site would be undefined here.
leak_scanned=0
leak_scan() {
    [ "$leak_scanned" = "1" ] && return 0
    leak_scanned=1
    [ -n "${log:-}" ] && [ -f "$log" ] || return 0
    # The log is folded once so a value spanning console line wraps still matches.
    # Every value this scan tests is newline-free BY CONSTRUCTION (the loaded map is
    # read line by line; the scratch secrets and the decoded pem are read through
    # tr -d), so a substring test on this folded log is exactly the wrapped-value match.
    flat_log="$(tr -d '\n' < "$log")"
    leak=""
    kind=""
    warn=""
    # Every loaded secret variable PRESENT in the central file is scanned, whatever
    # vendor this run belongs to (the file is shared; the scan is not). ALL value
    # matching — loaded variables and run-created values alike — is the builtin case
    # match, never a pipe into grep -q. On a MULTI-LINE stream that pipe is unsafe
    # under pipefail: a grep -q that exits at its first match leaves the feeder
    # dying on SIGPIPE (rc 141) and the pipeline fails as if nothing matched, so a
    # real leak would read as clean. On one folded single line GNU grep -q buffers
    # the whole line and does not invert (measured 2026-11-22) — but the case arm
    # keeps value matching out of that entire class, not one line-shape lucky case.
    # The shape arms below grep the log FILE directly — no pipe, no such class.
    if [ -n "${loaded[PRIVATE_KEY_BASE64]:-}" ]; then
        case "$flat_log" in *"${loaded[PRIVATE_KEY_BASE64]}"*) leak="yes"; kind="$kind loaded-private-key(base64)";; esac
        pem="$(printf '%s' "${loaded[PRIVATE_KEY_BASE64]}" | base64 -d 2>/dev/null || true)"
        flat_pem="$(printf '%s' "$pem" | tr -d '\n')"
        if [ -n "$flat_pem" ]; then
            case "$flat_log" in *"$flat_pem"*) leak="yes"; kind="$kind loaded-private-key(pem)";; esac
        fi
    fi
    if [ -n "${loaded[ANTHROPIC_API_KEY]:-}" ]; then
        case "$flat_log" in *"${loaded[ANTHROPIC_API_KEY]}"*) leak="yes"; kind="$kind loaded-api-key";; esac
    fi
    if [ -n "${loaded[TENANT_ID]:-}" ]; then
        # The owner decided (2026-11-22): a TENANT_ID in the log is NOT secret
        # material — it names a tenant, not a credential. Name the kind as a
        # warning, never the value, and the run still passes.
        case "$flat_log" in *"${loaded[TENANT_ID]}"*) warn="$warn tenant-id-in-log";; esac
    fi
    if [ "$vendor" = "graph" ]; then
        # the run-created client secret is this vendor's secret material: it may
        # exist only in the scratch file, never in the env file, the log or argv
        if [ -n "$graph_secret" ]; then
            case "$flat_log" in *"$graph_secret"*) leak="yes"; kind="$kind run-created-client-secret";; esac
        fi
    elif [ "$vendor" = "agenttokens" ]; then
        # both run-created client secrets are this vendor's secret material: they may
        # exist only in the scratch files, never in the env file, the log or argv
        if [ -n "$agenttokens_secret2" ]; then
            case "$flat_log" in *"$agenttokens_secret2"*) leak="yes"; kind="$kind run-created-client-secret-mapped";; esac
        fi
        if [ -n "$agenttokens_secret3" ]; then
            case "$flat_log" in *"$agenttokens_secret3"*) leak="yes"; kind="$kind run-created-client-secret-unmapped";; esac
        fi
    elif [ "$vendor" = "aca" ]; then
        # the run's caller key and vendor key values: they may exist only in the
        # vault, the scratch handoff and the in-cluster job - never here
        if [ -n "$aca_caller_key" ]; then
            case "$flat_log" in *"$aca_caller_key"*) leak="yes"; kind="$kind run-material-caller-key";; esac
        fi
        if [ -n "$aca_vendor_key" ]; then
            case "$flat_log" in *"$aca_vendor_key"*) leak="yes"; kind="$kind run-material-vendor-key";; esac
        fi
    fi
    if grep -qE 'gh[opsru]_[A-Za-z0-9]{20,}' "$log"; then
        leak="yes"; kind="$kind github-token-shape"
    fi
    if grep -qE 'sk-ant-[A-Za-z0-9_-]{20,}' "$log"; then
        leak="yes"; kind="$kind anthropic-key-shape"
    fi
    if grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "$log"; then
        leak="yes"; kind="$kind jwt-shape"
    fi
    if [ -n "$warn" ]; then
        echo "WARN: named non-secret material appears in the run log:$warn"
        echo "      values are never printed here; inspect the log yourself: $log"
    fi
    if [ -n "$leak" ]; then
        echo "FAIL: secret material appears in the run log:$kind"
        echo "      values are never printed here; inspect the log yourself: $log"
        exit 1
    fi
}

trap 'graph_destroy; agenttokens_destroy; aca_destroy; leak_scan' EXIT

# Wait for a run-created client secret to actually mint a token before the live
# cell starts (live finding 2026-11-22: Entra answers 401 for a brand-new secret
# for a short while, and CredProx can only answer 502 credential_unavailable —
# the cell would fail on propagation, not on the code). Polls the tenant's v2
# token endpoint with client_credentials every 5 s, up to
# CREDPROX_M46_SECRET_WAIT_SECONDS (default 120), until the HTTP code is 200.
# The secret travels to curl on STDIN only (--data-urlencode client_secret@-):
# it never reaches argv. Only the HTTP code is captured — the response body is
# never read, so no token exists anywhere outside curl's own buffers, and curl's
# stderr is discarded so no URL (which carries the tenant id) can reach the log.
# Prints only the elapsed line, or a FAIL naming the timeout; exit 1 on timeout
# still runs the armed destroy through the EXIT trap. Every poll is capped by
# curl --max-time, so a stalled request cannot outlive the advertised budget.
# $1 label  $2 client-id file (scratch)  $3 secret value  $4 scope
wait_secret_usable() {
    local label="$1" id_file="$2" secret="$3" scope="$4"
    local wait_budget="${CREDPROX_M46_SECRET_WAIT_SECONDS:-120}"
    local client_id code start now
    client_id="$(tr -d '\n' < "$id_file" 2>/dev/null)"
    if [ -z "$client_id" ]; then
        echo "FAIL: create reported success but $id_file is missing or empty; see $log"
        exit 1
    fi
    start="$(date +%s)"
    while :; do
        code="$(printf '%s' "$secret" | curl -s -o /dev/null -w '%{http_code}' \
            --max-time 15 \
            --data-urlencode "grant_type=client_credentials" \
            --data-urlencode "client_id=$client_id" \
            --data-urlencode "scope=$scope" \
            --data-urlencode 'client_secret@-' \
            "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" 2>/dev/null)" || code=""
        if [ "$code" = "200" ]; then
            now="$(date +%s)"
            echo "OK: $label secret usable after $((now - start)) s"
            return 0
        fi
        now="$(date +%s)"
        if [ $((now - start)) -ge "$wait_budget" ]; then
            echo "FAIL: the $label secret never minted a token within ${wait_budget} s of polling the tenant token endpoint; aborting before the live cell (the destroy below still runs)"
            exit 1
        fi
        sleep 5
    done
}

cd "$repo_root"
if [ "$vendor" = "graph" ]; then
    # The run creates exactly one app registration (+ its service principal and
    # one 30-day secret) and deletes it again before exiting; the scratch handoff
    # under $graph_scratch carries the secret to the live cell and is removed by
    # the same destroy.
    # Arm the destroy BEFORE the create: a create that fails partway can leave real
    # resources, and destroy is read-back based, so it is safe on partial or empty state.
    graph_app_created=1
    echo "--- live-graph-app.sh create ---"
    if ! "$repo_root/scripts/live-graph-app.sh" create 2>&1 | tee -a "$log"; then
        echo "FAIL: live-graph-app.sh create failed (values never shown); see $log"
        exit 1
    fi
    if [ -s "$graph_scratch/client-secret.txt" ]; then
        graph_secret="$(tr -d '\n' < "$graph_scratch/client-secret.txt")"
    fi
    if [ -z "$graph_secret" ]; then
        echo "FAIL: create reported success but the scratch client-secret.txt is missing or empty; see $log"
        exit 1
    fi
    wait_secret_usable "graph client" "$graph_scratch/client-id.txt" "$graph_secret" \
        "https://graph.microsoft.com/.default"
elif [ "$vendor" = "agenttokens" ]; then
    # The run creates exactly three app registrations (resource app + mapped and
    # unmapped client apps, with service principals and two 30-day secrets piped
    # straight to the scratch handoff) and deletes them again before exiting.
    # Arm the destroy BEFORE the create: a create that fails partway can leave real
    # resources, and destroy is read-back based, so it is safe on partial or empty state.
    agenttokens_apps_created=1
    echo "--- live-agenttokens-app.sh create ---"
    if ! "$repo_root/scripts/live-agenttokens-app.sh" create 2>&1 | tee -a "$log"; then
        echo "FAIL: live-agenttokens-app.sh create failed (values never shown); see $log"
        exit 1
    fi
    if [ -s "$agenttokens_scratch/app2-secret.txt" ]; then
        agenttokens_secret2="$(tr -d '\n' < "$agenttokens_scratch/app2-secret.txt")"
    fi
    if [ -s "$agenttokens_scratch/app3-secret.txt" ]; then
        agenttokens_secret3="$(tr -d '\n' < "$agenttokens_scratch/app3-secret.txt")"
    fi
    if [ -z "$agenttokens_secret2" ] || [ -z "$agenttokens_secret3" ]; then
        echo "FAIL: create reported success but a scratch client secret is missing or empty; see $log"
        exit 1
    fi
    # the handoff carries the resource app's id (v2 aud is the bare client id —
    # the live cell pins exactly that); the wait asks for that id under /.default,
    # the cell's own scope form and the only one with live PASS evidence (Entra
    # also accepts api://<id>/.default here, but that form is unproven). Both
    # secrets must propagate before the live cell can tell the mapped role from
    # the unmapped one:
    agenttokens_resource_id=""
    if [ -s "$agenttokens_scratch/resource-audience.txt" ]; then
        agenttokens_resource_id="$(tr -d '\n' < "$agenttokens_scratch/resource-audience.txt")"
    fi
    if [ -z "$agenttokens_resource_id" ]; then
        echo "FAIL: create reported success but the scratch resource-audience.txt is missing or empty; see $log"
        exit 1
    fi
    wait_secret_usable "mapped" "$agenttokens_scratch/app2-id.txt" "$agenttokens_secret2" "$agenttokens_resource_id/.default"
    wait_secret_usable "unmapped" "$agenttokens_scratch/app3-id.txt" "$agenttokens_secret3" "$agenttokens_resource_id/.default"
elif [ "$vendor" = "aca" ]; then
    # The aca live leg is SCRIPT-driven (disclosed: the app serves internal
    # ingress only, so no test process outside the environment can reach it).
    # apply lands the whole resource set incl vault material; push builds the
    # three images; deploy attaches identities and stamps revisions; verify
    # starts the acacheck job whose C-lines decide. destroy runs on every exit
    # path (trap) and the resource-group-gone read-back gates the PASS.
    # Arm the destroy BEFORE the create: a create that fails partway can leave real
    # resources, and destroy is read-back based, so it is safe on partial or empty state.
    aca_infra_created=1
    echo "--- live-m46-aca.sh apply (infra + vault material) ---"
    if ! "$repo_root/scripts/live-m46-aca.sh" apply 2>&1 | tee -a "$log"; then
        echo "FAIL: live-m46-aca.sh apply failed; see $log"
        exit 1
    fi
    if [ -s "$aca_scratch/aca-secrets.env" ]; then
        while IFS='=' read -r k v; do
            case "$k" in
                ACA_CALLER_KEY) aca_caller_key="$v" ;;
                ACA_VENDOR_KEY) aca_vendor_key="$v" ;;
            esac
        done < "$aca_scratch/aca-secrets.env"
    fi
    if [ -z "$aca_caller_key" ] || [ -z "$aca_vendor_key" ]; then
        echo "FAIL: apply reported success but the scratch secret handoff is missing or empty; see $log"
        exit 1
    fi
    echo "--- live-m46-aca.sh push ---"
    if ! "$repo_root/scripts/live-m46-aca.sh" push 2>&1 | tee -a "$log"; then
        echo "FAIL: live-m46-aca.sh push failed; see $log"
        exit 1
    fi
    echo "--- live-m46-aca.sh deploy ---"
    if ! "$repo_root/scripts/live-m46-aca.sh" deploy 2>&1 | tee -a "$log"; then
        echo "FAIL: live-m46-aca.sh deploy failed; see $log"
        exit 1
    fi
    echo "--- live-m46-aca.sh verify (job C-lines decide) ---"
    if ! "$repo_root/scripts/live-m46-aca.sh" verify 2>&1 | tee -a "$log"; then
        echo "FAIL: live-m46-aca.sh verify failed; see $log"
        exit 1
    fi
fi

if dotnet test tests/CredProx.LiveTests -c Release --filter "$test_filter" --logger "console;verbosity=detailed" 2>&1 | tee -a "$log"; then
    tests_ok=1
else
    tests_ok=0
fi

if [ "$vendor" = "graph" ]; then
    graph_destroy
elif [ "$vendor" = "agenttokens" ]; then
    agenttokens_destroy
elif [ "$vendor" = "aca" ]; then
    aca_destroy
fi

# Happy path: the destroys above already landed, so scan inline before the PASS
# tail; every failing exit path reaches the same function from the trap instead
# (once-guarded, so this runs the scan exactly once per run).
leak_scan

if [ "$graph_destroy_rc" -ne 0 ]; then
    echo "FAIL: the run-created Entra app registration was not fully deleted (read-back); see $log"
    exit 1
fi
if [ "$agenttokens_destroy_rc" -ne 0 ]; then
    echo "FAIL: the run-created Entra app registrations were not fully deleted (read-back); see $log"
    exit 1
fi
if [ "$aca_destroy_rc" -ne 0 ]; then
    echo "FAIL: the run's Azure resources were not fully deleted (read-back incl resource group); see $log"
    exit 1
fi

if [ "$tests_ok" -ne 1 ]; then
    echo "FAIL: the live test run did not pass; see $log"
    exit 1
fi

observed="$(grep -m1 'OBSERVED ' "$log" || true)"
if [ -n "$observed" ]; then
    echo "PASS $vendor: ${observed#*OBSERVED }"
    exit 0
fi

skip_line="$(grep -m1 'SKIP (live):' "$log" || true)"
if [ -n "$skip_line" ]; then
    echo "SKIP: the live cell did not run."
    echo "      $skip_line"
    exit 2
fi

echo "FAIL: the live cell neither ran nor skipped cleanly; no OBSERVED line; see $log"
exit 1
