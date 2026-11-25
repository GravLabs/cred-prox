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
# registrations (one resource app with an api:// identifier and two app roles,
# docs-read and model-call, both assigned to both client apps, each client app
# with one secret piped straight to scratch), and the same create-read-back /
# destroy-read-back discipline. The foundrylocal run reuses that lifecycle script
# and its scratch handoff UNCHANGED — the same three apps, the same waits, the
# same discipline — because its proof is the same Entra admission story (mapped
# client admitted, unmapped client 401) on a free loopback local model instead of
# a paid cloud endpoint. After either create the runner first WAITS for
# Entra to propagate the brand-new client secret - it polls the tenant's v2 token
# endpoint with client_credentials every 5 s (up to
# CREDPROX_M46_SECRET_WAIT_SECONDS, default 120) until a token comes back 200,
# because a cell that starts against an unpropagated secret only ever sees a 401
# the vendor cannot serve (live finding 2026-11-22). On the agenttokens leg (and
# its foundrylocal twin, which shares these waits through the same script) it
# then waits for that token to carry BOTH app roles - Entra lands a fresh role
# assignment into issued tokens only after a delay (up to
# CREDPROX_M46_ROLE_WAIT_SECONDS, default 300; live finding 2026-11-23). The aca
# run drives
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
    foundrylocal)
        required="TENANT_ID"
        # the FoundryLocal live cells (a REAL Entra caller token against the
        # sample gate: mapped client 200 through the loopback model, unmapped
        # client 401 with nothing moved, a tool no rule admits 403 at the gate),
        # the vendor's offline legs (env contract, scratch contract, runner
        # wiring) and the env-contract legs. No billable gate: Foundry Local on
        # loopback costs nothing per call.
        test_filter="FullyQualifiedName~FoundryLocal|FullyQualifiedName~LiveEnvContractTests"
        ;;
    aca)
        required="TENANT_ID"
        # the lifecycle script's canned-az read-back cells, the acacheck loopback
        # cell and the env-contract legs - the aca LIVE leg is the script-driven
        # leg below (internal ingress: no xunit cell can reach it; disclosed)
        test_filter="FullyQualifiedName~Aca|FullyQualifiedName~LiveEnvContractTests"
        ;;
    azureopenai)
        required="AZURE_OPENAI_LOCATION AZURE_OPENAI_MODEL AZURE_OPENAI_MODEL_VERSION AZURE_OPENAI_SKU AZURE_OPENAI_DEPLOYMENT_SKU"
        # the AzureOpenAI live cell (ONE tiny chat against the deployment THIS run
        # creates and later destroys — creating the resource is itself the billable
        # action, so without CREDPROX_M52_BILLABLE=1 the run creates nothing, dials
        # nothing, spends nothing) plus this vendor's offline legs whose names carry
        # the vendor token (env contract and the scaffold pins). The canned-runner
        # and canned-helper witnesses are deliberately named Aoai*, so this filter
        # does NOT select them: a leg the runner execs must never exec a nested
        # runner - the naming invariant enforced by NamesCarryNoRunnerFilterToken.
        test_filter="FullyQualifiedName~AzureOpenAI|FullyQualifiedName~LiveEnvContractTests"
        ;;
    *)
        echo "SKIP: no live vendor '$vendor' (known vendors: githubapp, aigateway, graph, agenttokens, foundrylocal, aca, azureopenai)"
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
for stale_vendor in githubapp aigateway graph agenttokens foundrylocal aca azureopenai; do
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
# The default rides `-`, not `:-`: a name EXPORTED EMPTY is exactly the
# dangerous shape - the empty string is already the first refused arm below,
# and the old `:-` papered it over with the 120 default.
case "${CREDPROX_M46_SECRET_WAIT_SECONDS-120}" in
    ''|*[!0-9]*|0|0*|???????*)
        echo "REFUSED: CREDPROX_M46_SECRET_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits"
        exit 2 ;;
esac

# The azureopenai role-propagation wait (M52 part B) gets the same refusal: the
# wait below compares numbers, and a value such as "5m" must never let its loop
# run on while a created resource is held.
# Same `-` choice: an exported-empty name is refused, an unset one still
# defaults to 300.
case "${CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS-300}" in
    ''|*[!0-9]*|0|0*|???????*)
        echo "REFUSED: CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits"
        exit 2 ;;
esac

# The M46 role-propagation wait (wait_roles_in_token below) gets the same
# refusal. It was the last wait budget with NO shape guard anywhere in the
# file: flipping its expansion to `-` without this block would turn an
# exported-empty value into the very hang the guards above exist to refuse,
# so both halves land together - every non-numeric shape (including empty)
# is refused by name before anything is created, and unset still defaults
# to 300.
case "${CREDPROX_M46_ROLE_WAIT_SECONDS-300}" in
    ''|*[!0-9]*|0|0*|???????*)
        echo "REFUSED: CREDPROX_M46_ROLE_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits"
        exit 2 ;;
esac

# The az vendors (Entra's graph, agenttokens and foundrylocal, aca's Azure
# resource set) ride the owner's az sign-in; azureopenai's az and curl gates
# moved into its armed create leg below, because its zero-spend run needs
# neither. The gates below are read-only; the only writes are the create/destroy
# pairs further down, and everything they create is deleted again before this
# script exits — the destroy read-back flips the run to FAIL if anything survives.
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
aoai_scratch="${CREDPROX_M52_AOAI_SCRATCH:-/tmp/credprox-m52-aoai}"
aoai_principal=""
aoai_infra_created=0
aoai_destroy_rc=0
aoai_destroy() {
    # once, on every exit path after create was armed (trap EXIT)
    [ "$aoai_infra_created" = "1" ] || return 0
    aoai_infra_created=0
    echo "--- live-m52-aoai.sh destroy (read-backs decide, group included) ---"
    if "$repo_root/scripts/live-m52-aoai.sh" destroy 2>&1 | tee -a "$log"; then
        # count over the whole file, no tail|grep pipe: aoai_destroy runs at most
        # once per run, and the count reader consumes the stream to EOF (the aca
        # note above on SIGPIPE applies to any future change here).
        if [ "$(grep -c 'SKIPPED: role-assignment read-back' "$log" || true)" -gt 0 ]; then
            echo "aoai destroy: resource group gone; the role-assignment check was SKIPPED (unresolved account scope - NOT a confirmed zero, see the destroy lines)"
        else
            echo "aoai destroy: read-back clean (resource group gone, role assignments zero)"
        fi
    else
        aoai_destroy_rc=1
        echo "aoai destroy: READ-BACK FAILED - leftovers remain; see above"
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
        # $vendor is agenttokens or foundrylocal here (the only arms that set the
        # created flag); the pinned string stays byte-identical for agenttokens
        echo "$vendor destroy: read-back clean"
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

# Opt-in extras (M53): agenttokens carries the billable-cell go-ahead through when the
# central file sets it — CREDPROX_M53_BILLABLE=1 plus ANTHROPIC_API_KEY, both of which the
# cell skips without. Absent means skipped with a reason, never a failure; nothing else
# is ever passed through, and the leak scan still reads only the loaded map.
if [ "$vendor" = "agenttokens" ]; then
    for name in CREDPROX_M53_BILLABLE ANTHROPIC_API_KEY; do
        if [ -n "${loaded[$name]:-}" ]; then
            export "$name=${loaded[$name]}"
        fi
    done
fi

# Opt-in extras (M54): foundrylocal's cloud leg is the vendor's one billable cell,
# armed by CREDPROX_M54_BILLABLE=1 plus ANTHROPIC_API_KEY in the central file, both
# of which the cell skips without. Unlike agenttokens the key travels ONLY with the
# go-ahead: an ANTHROPIC_API_KEY sitting in the central file without the flag
# exports neither name, so a stray key can never arm a billable call. Absent means
# skipped with a reason, never a failure; the leak scan still reads only the loaded map.
if [ "$vendor" = "foundrylocal" ] && [ "${loaded[CREDPROX_M54_BILLABLE]:-}" = "1" ]; then
    export CREDPROX_M54_BILLABLE=1
    if [ -n "${loaded[ANTHROPIC_API_KEY]:-}" ]; then
        export ANTHROPIC_API_KEY="${loaded[ANTHROPIC_API_KEY]}"
    fi
fi

# Opt-in extra (M52): the azureopenai run CREATES its own Azure OpenAI resource —
# the creation is the billable action — so the go-ahead now arms CREATE, not a dial
# into a standing one: CREDPROX_M52_BILLABLE=1 inside an azureopenai run alone (a
# stray flag outside the run exports nothing). The endpoint and deployment the live
# cell dials are RUNNER-EXPORTED after create from the scratch names handoff, never
# read from the central file; without the go-ahead neither name is exported
# anywhere and the live cell skips with a reason, spending nothing. The leak scan
# still reads only the loaded map.
aoai_armed=0
if [ "$vendor" = "azureopenai" ] && [ "${loaded[CREDPROX_M52_BILLABLE]:-}" = "1" ]; then
    export CREDPROX_M52_BILLABLE=1
    aoai_armed=1
fi

if [ "$vendor" = "graph" ] || [ "$vendor" = "agenttokens" ] || [ "$vendor" = "foundrylocal" ] || [ "$vendor" = "aca" ]; then
    if ! command -v az >/dev/null 2>&1; then
        echo "SKIP: the $vendor vendor needs the az CLI on PATH (see docs/live-testing.md)"
        exit 2
    fi
    if ! az account get-access-token >/dev/null 2>&1; then
        echo "SKIP: no active az login for the $vendor vendor (run: az login)"
        exit 2
    fi
fi

# The graph, agenttokens and foundrylocal runs poll Entra's token endpoint to
# wait for a freshly created client secret to propagate; that needs curl before
# any create can spend anything. (The aca run has no such wait: its vault
# material is written, not minted by Entra.)
if [ "$vendor" = "graph" ] || [ "$vendor" = "agenttokens" ] || [ "$vendor" = "foundrylocal" ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "SKIP: the $vendor vendor waits for a created client secret to become usable and needs curl on PATH"
        exit 2
    fi
fi

# (M52 part B) The zero-billable preflight dialed the owner's STANDING endpoint and
# died with that form: an armed run now proves its OWN endpoint by dialing it
# authenticated in the role wait below (a role that never lands FAILs the leg before
# the cell spends a call), and an unarmed run dials nothing at all.

# The foundrylocal run answers a loopback Foundry Local server, which is not part
# of the harness and authenticates nothing: without it the live cell has no model
# to call. Checked BEFORE any create, so a missing local model spends no Entra
# resources; SKIP (exit 2), never a failure.
if [ "$vendor" = "foundrylocal" ]; then
    fl_base="${CREDPROX_FOUNDRYLOCAL_URL:-http://127.0.0.1:5273}"
    if ! curl -s --max-time 10 -o /dev/null "$fl_base/v1/models"; then
        echo "SKIP: no Foundry Local server answered $fl_base/v1/models (start Foundry Local or set CREDPROX_FOUNDRYLOCAL_URL)"
        exit 2
    fi
    # One shared predicate for the model, checked BEFORE any create. The id is
    # FOUNDRY_LOCAL_MODEL from the central env file, defaulting to the model the
    # sample's appsettings names; /v1/models also lists catalog entries that
    # were never downloaded, so presence there is NOT proof — one tiny chat to
    # THIS id must answer before the run is armed. The validated id is then
    # EXPORTED, so the live cell calls exactly the model this preflight proved;
    # nothing anywhere picks a model by catalog order.
    fl_model="${FOUNDRY_LOCAL_MODEL:-}"
    if [ -z "$fl_model" ]; then
        fl_model="$(awk '/"FoundryLocal"/{f=1} f && match($0, /"Model": "[^"]*"/) {print substr($0, RSTART+10, RLENGTH-11); exit}' \
            "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/samples/FoundryLocalAgent/appsettings.json")"
    fi
    if [ -z "$fl_model" ]; then
        echo "FAIL: no model id to validate: FOUNDRY_LOCAL_MODEL is unset and the sample appsettings names no FoundryLocal Model"
        exit 1
    fi
    fl_probe="$(curl -s --max-time 60 -w '\n%{http_code}' -H 'Content-Type: application/json' \
        -d "{\"model\":\"$fl_model\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"max_tokens\":1}" \
        "$fl_base/v1/chat/completions")" || fl_probe=""
    fl_code="${fl_probe##*$'\n'}"
    fl_resp="${fl_probe%$'\n'*}"
    case "$fl_resp" in
        *'"choices"'*) fl_answers=1 ;;
        *) fl_answers=0 ;;
    esac
    if [ "$fl_code" != "200" ] || [ "$fl_answers" != "1" ]; then
        echo "SKIP: model '$fl_model' is not loaded and answering at $fl_base (http $fl_code, body: $(printf '%s' "$fl_resp" | head -c 200)) - download it or set FOUNDRY_LOCAL_MODEL in $display to an id the server has loaded"
        exit 2
    fi
    export FOUNDRY_LOCAL_MODEL="$fl_model"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$(mktemp "${TMPDIR:-/tmp}/credprox-live-run-$vendor.XXXXXX.log")"
echo "log: $log"
# Post-release item 4 (2026-11-25): every run created a log and removed nothing -
# the pile grows without bound (961 orphan files observed in /tmp). A sweep on
# each run: only this script's OWN pattern, only plain files, only older than
# 24h (own fresh log and any concurrent run's log can never match). Logs stay
# kept as evidence - the leak-scan witnesses read the log back after a PASS run -
# so hygiene is the sweep, not deletion; the name now carries the vendor.
swept_logs=0
while IFS= read -r -d '' stale_log; do
    rm -f "$stale_log" 2>/dev/null && swept_logs=$((swept_logs+1))
done < <(find "${TMPDIR:-/tmp}" -maxdepth 1 -type f -mmin +1440 \
    \( -name 'credprox-live-run.*.log' -o -name 'credprox-live-run-*.log' \) -print0 2>/dev/null)
if [ "$swept_logs" -gt 0 ]; then
    echo "swept $swept_logs orphan run log(s) older than 24h"
fi

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
    if [ -n "$aoai_principal" ]; then
        # the armed azureopenai run's signed-in principal object id (its role
        # assignee): it identifies the OWNER's user, so a GUID match is leak
        # material - the helper and the role wait capture it in variables only
        # and never print it; the names-handoff and counts are what may print.
        case "$flat_log" in *"$aoai_principal"*) leak="yes"; kind="$kind aoai-principal-guid";; esac
    fi
    if [ "$vendor" = "graph" ]; then
        # the run-created client secret is this vendor's secret material: it may
        # exist only in the scratch file, never in the env file, the log or argv
        if [ -n "$graph_secret" ]; then
            case "$flat_log" in *"$graph_secret"*) leak="yes"; kind="$kind run-created-client-secret";; esac
        fi
    elif [ "$vendor" = "agenttokens" ] || [ "$vendor" = "foundrylocal" ]; then
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

trap 'graph_destroy; agenttokens_destroy; aca_destroy; aoai_destroy; leak_scan' EXIT

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
    local wait_budget="${CREDPROX_M46_SECRET_WAIT_SECONDS-120}"
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

# Entra answers a freshly-created secret with 401 for a short while (M46 finding,
# wait_secret_usable above); a freshly-ASSIGNED app role has the same propagation
# delay before it appears in issued tokens. The sample's routes name roles
# (docs-read for docs, model-call for the model), so a token that lands without
# both roles 403s in the live cell exactly like the harness gap this leg exists
# to catch (live run 2) — indistinguishable from a real regression. Poll until
# the mapped caller's token carries BOTH. Unlike wait_secret_usable this probe
# reads the body (the roles live in the access token's claims), but the body and
# the token are never printed and never enter argv or a file: the token travels
# to curl on STDIN only, the claims are decoded in shell variables, and only the
# pass/fail lines print. Budget: CREDPROX_M46_ROLE_WAIT_SECONDS (default 300).
# $1 label  $2 client-id file (scratch)  $3 secret value  $4 scope
wait_roles_in_token() {
    local label="$1" id_file="$2" secret="$3" scope="$4"
    local wait_budget="${CREDPROX_M46_ROLE_WAIT_SECONDS-300}"
    local client_id body token payload claims has_roles has_docs has_model start now
    client_id="$(tr -d '\n' < "$id_file" 2>/dev/null)"
    if [ -z "$client_id" ]; then
        echo "FAIL: create reported success but $id_file is missing or empty; see $log"
        exit 1
    fi
    start="$(date +%s)"
    while :; do
        body="$(printf '%s' "$secret" | curl -s --max-time 15 \
            --data-urlencode "grant_type=client_credentials" \
            --data-urlencode "client_id=$client_id" \
            --data-urlencode "scope=$scope" \
            --data-urlencode 'client_secret@-' \
            "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" 2>/dev/null)" || body=""
        case "$body" in
            *'"access_token"'*) ;;
            *) body="";;
        esac
        if [ -n "$body" ]; then
            token="${body#*'"access_token":"'}"
            token="${token%%\"*}"
            payload="$(printf '%s' "$token" | cut -d. -f2 | tr '_-' '/+')"
            while [ $(( ${#payload} % 4 )) -ne 0 ]; do payload="${payload}="; done
            claims="$(printf '%s' "$payload" | base64 -d 2>/dev/null)" || claims=""
            has_roles=0; has_docs=0; has_model=0
            case "$claims" in *'"roles"'*) has_roles=1;; esac
            case "$claims" in *docs-read*) has_docs=1;; esac
            case "$claims" in *model-call*) has_model=1;; esac
            if [ "$has_roles" = "1" ] && [ "$has_docs" = "1" ] && [ "$has_model" = "1" ]; then
                now="$(date +%s)"
                echo "OK: $label token carries both app roles after $((now - start)) s"
                return 0
            fi
        fi
        now="$(date +%s)"
        if [ $((now - start)) -ge "$wait_budget" ]; then
            echo "FAIL: the $label token never carried BOTH app roles (docs-read and model-call) within ${wait_budget} s of polling the tenant token endpoint; aborting before the live cell (the destroy below still runs)"
            exit 1
        fi
        sleep 5
    done
}

# A freshly-assigned role needs up to five minutes to take effect on the resource
# (Microsoft: a 403 right after the assignment means wait and retry, not
# troubleshoot - see the citations in live-m52-aoai.sh). Poll the run's OWN
# endpoint's data-plane MODELS LIST (GET /openai/models, the GA release named in
# the variable below) with a bearer token for the cognitive-services scope:
# a zero-cost, authorised, read-only call, and the role this run grants carries
# Microsoft.CognitiveServices/accounts/OpenAI/*/read, which admits it (Azure
# built-in role definitions, ai-machine-learning page). 200 = the role is live;
# 401 and 403 keep polling (the token is valid; the role decision has not reached
# this resource yet) and so does the no-answer code 000 (the fresh
# custom-subdomain DNS may still be resolving - the account's own provisioning
# enum carries a ResolvingDNS state); anything else is a dial no waiting fixes.
# Live run 4 (2026-11-25) chose this probe the hard way: the OLD deployments-list
# verb is not in the current data-plane API, so a correctly authorised caller got
# 404 and the probe aborted - the right call on the wrong target.
# A timeout FAILs BEFORE the live cell spends a call on
# it, and the armed destroy still runs through the trap. The bearer never enters
# argv (curl reads its header from stdin config) and is never printed; only the
# deadline, codes and elapsed time print. Budget:
# CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS (default 300, shape-refused at the top).
# $1 endpoint base (no trailing slash)
# One named variable for the probe's api-version. 2024-10-21 is the GA release of
# the Azure OpenAI data-plane inference specification (Azure OpenAI reference
# page) and the view the Models list operation is documented under (its REST page,
# fetched 2026-11-25). The reference's chat-route EXAMPLE names the older GA
# 2024-06-01 - the same specification at an earlier release - so the probe and the
# sample's chat route deliberately do NOT share a version, stated rather than
# papered over; both are GA releases with the operations they dial.
AOAI_DATA_PLANE_API_VERSION="2024-10-21"
wait_aoai_role_active() {
    local base="$1"
    local wait_budget="${CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS-300}"
    local token code start now
    echo "aoai role wait: polling the created endpoint up to ${wait_budget} s - deadline $(date -u -d "+${wait_budget} seconds" +%H:%M:%SZ) UTC"
    token="$(az account get-access-token --scope https://cognitiveservices.azure.com/.default --query accessToken -o tsv 2>/dev/null)" || token=""
    if [ -z "$token" ]; then
        echo "FAIL: no bearer token for the role-propagation probe; aborting before the live cell (the destroy below still runs)"
        exit 1
    fi
    start="$(date +%s)"
    while :; do
        code="$(printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -s --max-time 15 -K - -o /dev/null -w '%{http_code}' "$base/openai/models?api-version=$AOAI_DATA_PLANE_API_VERSION" 2>/dev/null)" || code=""
        case "$code" in
            200)
                now="$(date +%s)"
                echo "OK: the role is live on the endpoint after $((now - start)) s"
                return 0 ;;
            401|403|000|'') ;;
            *)
                echo "FAIL: the endpoint answered http $code to an authenticated models list - that is not role propagation; aborting before the live cell (the destroy below still runs)"
                exit 1 ;;
        esac
        now="$(date +%s)"
        if [ $((now - start)) -ge "$wait_budget" ]; then
            echo "FAIL: the role never went live within ${wait_budget} s of polling the endpoint (last answer: ${code:-no-code}); aborting before the live cell (the destroy below still runs)"
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
elif [ "$vendor" = "agenttokens" ] || [ "$vendor" = "foundrylocal" ]; then
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
    # The mapped token must actually CARRY both app roles before the cell runs:
    # fresh role assignments reach issued tokens only after an Entra delay, and a
    # token without model-call would 403 like the harness gap this leg fixes
    # (live run 2). The unmapped caller needs no wait — it must stay refused
    # whatever roles its token carries.
    wait_roles_in_token "mapped" "$agenttokens_scratch/app2-id.txt" "$agenttokens_secret2" "$agenttokens_resource_id/.default"
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

if [ "$vendor" = "azureopenai" ] && [ "$aoai_armed" = "1" ]; then
    # The armed leg creates its own resource (owner's go-ahead; the lead runs it).
    # Gates FIRST: this path writes to a subscription, so az sign-in and curl (the
    # role wait) are required HERE - an unarmed zero-spend run never reaches them
    # and needs neither.
    if ! command -v az >/dev/null 2>&1; then
        echo "SKIP: the armed azureopenai leg creates resources and needs the az CLI on PATH (see docs/live-testing.md)"
        exit 2
    fi
    if ! az account get-access-token >/dev/null 2>&1; then
        echo "SKIP: no active az login for the armed azureopenai leg (run: az login)"
        exit 2
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "SKIP: the armed azureopenai leg waits for its role assignment to go live and needs curl on PATH"
        exit 2
    fi
    # The role assignee's object id, for the leak scan only: captured into a
    # variable, never exported, never printed (the helper resolves its own copy;
    # an empty value simply disables that scan arm).
    aoai_principal="$(az ad signed-in-user show --query id -o tsv 2>/dev/null)" || aoai_principal=""
    # Arm the destroy BEFORE the create: a create that fails partway can leave
    # real resources, and the destroy is read-back based, so it is safe on
    # partial or empty state. Destroy deletes ONLY the group rg.txt records as
    # this run's own - a create that died before recording its group is reported
    # as an unconfirmed read-back (non-zero), never swept by guessing the fixed
    # name: a group this run did not create is not this run's to delete.
    aoai_infra_created=1
    echo "--- live-m52-aoai.sh create (rg + account + deployment + role) ---"
    if ! "$repo_root/scripts/live-m52-aoai.sh" create 2>&1 | tee -a "$log"; then
        echo "FAIL: live-m52-aoai.sh create failed (ids never shown); see $log"
        exit 1
    fi
    aoai_endpoint=""
    aoai_deployment=""
    if [ -s "$aoai_scratch/endpoint.txt" ] && [ -s "$aoai_scratch/deployment.txt" ]; then
        aoai_endpoint="$(tr -d '\n' < "$aoai_scratch/endpoint.txt")"
        aoai_deployment="$(tr -d '\n' < "$aoai_scratch/deployment.txt")"
    fi
    if [ -z "$aoai_endpoint" ] || [ -z "$aoai_deployment" ]; then
        echo "FAIL: create reported success but the scratch names handoff is missing or empty; see $log"
        exit 1
    fi
    # The live cell's env contract is unchanged - the dial names come from the
    # runner's environment; only their SOURCE is now the run's own resource, and
    # the cell validates the shape (the same IsPlausibleEndpoint the old central
    # file was checked with).
    export AZURE_OPENAI_ENDPOINT="$aoai_endpoint"
    export AZURE_OPENAI_DEPLOYMENT="$aoai_deployment"
    wait_aoai_role_active "${aoai_endpoint%/}"
fi

# Runner-only marker: the vendor-scratch-gated live cells require this variable
# to name THIS leg on top of the run-created handoff, so leftover scratch from
# any interrupted run — this vendor's or another's — can never arm a live cell
# inside an offline test run. It is exported here and nowhere else: never read
# from the central env file, so a bare dotnet test process never carries it.
export CREDPROX_LIVE_VENDOR="$vendor"

if dotnet test tests/CredProx.LiveTests -c Release --filter "$test_filter" --logger "console;verbosity=detailed" 2>&1 | tee -a "$log"; then
    tests_ok=1
else
    tests_ok=0
fi

if [ "$vendor" = "graph" ]; then
    graph_destroy
elif [ "$vendor" = "agenttokens" ] || [ "$vendor" = "foundrylocal" ]; then
    agenttokens_destroy
elif [ "$vendor" = "aca" ]; then
    aca_destroy
elif [ "$vendor" = "azureopenai" ]; then
    aoai_destroy
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
if [ "$aoai_destroy_rc" -ne 0 ]; then
    echo "FAIL: the run's Azure OpenAI resources were not fully deleted (read-back incl resource group); see $log"
    exit 1
fi

if [ "$tests_ok" -ne 1 ]; then
    echo "FAIL: the live test run did not pass; see $log"
    exit 1
fi

observed="$(grep 'OBSERVED ' "$log" || true)"
if [ -n "$observed" ]; then
    # Post-release item 3 (2026-11-25): a vendor's run may print one OBSERVED line
    # per live cell (several vendors legitimately run several cells), and the old
    # grep -m1 silently dropped every line but the first from the PASS record.
    # Aggregate: every payload joins into the one PASS line.
    joined=""
    while IFS= read -r observed_line; do
        [ -n "$observed_line" ] || continue
        payload="${observed_line#*OBSERVED }"
        if [ -n "$joined" ]; then joined="$joined; $payload"; else joined="$payload"; fi
    done <<< "$observed"
    echo "PASS $vendor: $joined"
    exit 0
fi

skip_line="$(grep -m1 'SKIP (live):' "$log" || true)"
if [ -n "$skip_line" ]; then
    echo "SKIP: the live cell did not run."
    echo "      $skip_line"
    echo "      kept for inspection: $log"
    exit 2
fi

echo "FAIL: the live cell neither ran nor skipped cleanly; no OBSERVED line; see $log"
exit 1
