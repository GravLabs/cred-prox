#!/usr/bin/env bash
# M52 part B: the Azure OpenAI resource lifecycle for the azureopenai live vendor.
#   create   - one dedicated resource group, one Azure OpenAI account (kind OpenAI)
#              with LOCAL (key) AUTH DISABLED and a custom domain (required for the
#              Entra ID auth this vendor dials), one chat deployment of the model
#              the central env file names, and one "Cognitive Services OpenAI User"
#              role assignment for the signed-in az principal scoped to the account.
#              The fixed group name must be FREE: if az group exists already
#              reports it, create refuses BEFORE any write and this script never
#              deletes a group it did not create - the owner clears a leftover by
#              hand only after checking it holds just credprox-m52 resources.
#              rg.txt and location.txt are written only after the group create
#              succeeds, so a recorded group is by construction a group this run
#              created, and the recorded location is where that group lives.
#              Read-backs before any handoff is written: provisioningState
#              Succeeded (polled again after the resource update, which can
#              re-provision the account), disableLocalAuth read back true after
#              the resource update that sets it, the deployment listed, exactly
#              one role assignment at the account scope.
#   destroy  - deletes ONLY the resource group named in rg.txt (everything inside
#              goes with it) - never the fixed name as a guess. No rg.txt means the
#              run never recorded a group it created: destroy issues NO group
#              delete, prints a SKIPPED line for the group, and exits non-zero
#              because nothing about a group was confirmed. Two guards run BEFORE
#              any az write (the signed-in probe excepted): a malformed purge budget is refused up front,
#              and a handoff that records a group and an account but no
#              location.txt dies there too - destroy scopes the purge from the
#              recorded location, never from an environment a retry might not
#              export. With a recorded group
#              it waits (bounded) for the group to report gone, then PURGES the
#              soft-deleted account at the recorded location (a deleted Cognitive
#              Services account keeps
#              its name reserved until purged - the docs do not state how long
#              the hold lasts, UNVERIFIED, so what the run verifies is its own
#              purge, not a retention window) and reads the soft-deleted list
#              back, POLLING because the purge settles asynchronously: absent =
#              clean; still-listed OR could-not-verify (the list read never
#              answered cleanly) = FAILED - an unanswered question never borrows
#              the clean verdict's exit. A purge block the run never reached
#              reports not-attempted, not a verdict it did not earn.
#              The purge VERB's exit is not the verdict (an account that was
#              never created makes it error too) - the read-back decides. Then
#              it reads the
#              account-scope role assignment back: gone scope or zero assignments
#              is the zero; an unresolved account prints a SKIPPED line and is NOT
#              a confirmed zero (the destroy-r2 discipline: the exit code reflects
#              the read-back, never the hope). The scratch dir is removed ONLY
#              when every read-back confirmed clean; a failed or skipped
#              read-back RETAINS it, because the recorded names are what let a
#              retry name - and so confirm - what it still has to clean.
#   --dry-run- prints the plan; touches nothing.
#
# Only a seat's LEAD runs create/destroy against a real subscription; read verbs
# are fine anywhere. The runner (live-run.sh azureopenai) arms create only under
# the owner's billable go-ahead and destroys in its EXIT trap whatever exists:
# resource-group-scoped teardown makes partial creates cleanable even when the
# account or deployment never came up.
#
# The signed-in principal's id and the account's resource id (which carries the
# subscription id) are captured in variables only: they never print, never enter
# any file, and every az WRITE's stdout is sent to /dev/null so no assignment or
# group object can land a GUID in the run log. On a write failure stderr is
# captured and only the az error CODE is printed (live run 2 failed blind
# because the whole stream was discarded; the message body can carry ids, so
# only the code token crosses). Prints name and counts only.
#
# Offline contract test (AoaiInfraScriptTests): shadow a stub az at the front of
# PATH, point CREDPROX_M52_AOAI_SCRATCH at a temp dir and set the five
# AZURE_OPENAI_* names; the stub logs verb lines only (never flags - no planted id
# can ride the instrument), so create's ORDER, the
# partial-create teardown, the refusal guard and the read-back refusals are all
# decidable without a subscription, and the principal id the stub PLANTS proves
# no GUID reaches any output stream.
#
# Every verb and flag below was verified against `az <verb> --help` ON THIS HOST
# (2026-11-25), not only against the docs - the docs were wrong once already
# (live run 1) and the CLI was wrong the second way (live run 2): list-deleted
# takes NO location or scope argument at all - only the global ones - and
# `--location` on it fails with rc 2 "unrecognized arguments", which is why its
# purge read-back could never come back clean. The soft-deleted-list read-back
# therefore filters by NAME inside --query: the account name is a global
# namespace (it reserves its own DNS subdomain), so the name filter is exact.
# Deliberately NOT filtered by location: the list's location field is an
# unverified shape (display form vs short form - the subscription was empty when
# checked), and a format-mismatched location filter would read a still-listed
# account as absent: a fake clean. The recorded location scopes the purge VERB.
#   az group create / exists / delete --yes --no-wait:
#     https://learn.microsoft.com/en-us/cli/azure/group
#   az cognitiveservices account create (--kind, --sku, --custom-domain, --yes)
#     and show, account purge and account list-deleted (both
#     GA; the purge example names location, resource group and name:
#     az cognitiveservices account purge --location eastus --resource-group ...
#     --name ...):
#     https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account
#   deployment create (--deployment-name,
#     --model-name, --model-version, --model-format OpenAI, --sku-name,
#     --sku-capacity - the latter two verified this host as accepted aliases of
#     --sku / --capacity) and deployment show (--deployment-name included):
#     https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account
#     https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account/deployment
#     kind OpenAI + --sku s0 + --custom-domain example (Azure CLI tab):
#     https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/create-resource
#   custom subdomain required for Entra ID auth:
#     https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity
#     https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-custom-subdomains
#   disableLocalAuth is a documented account PROPERTY (Azure Policy, ARM and
#     PowerShell halves - that page carries NO Azure CLI verb). Live run 1
#     FALSIFIED the derived --api-properties composition: the flag lands on
#     properties.apiProperties and leaves properties.disableLocalAuth unset, so
#     the read-back correctly refused at zero spend. The property is set after
#     provisioning with the generic ARM PATCH (az resource update, documented
#     with the literal --ids $id --set properties.x=y example form):
#     https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth
#     https://learn.microsoft.com/en-us/cli/azure/resource
#     https://learn.microsoft.com/en-us/rest/api/aiservices/accountmanagement/accounts/get
#   role name "Cognitive Services OpenAI User" (Assign a role section):
#     https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity
#   az role assignment create --role/--assignee-object-id/--assignee-principal-type/
#     --scope and list (same flags): https://learn.microsoft.com/en-us/cli/azure/role/assignment
#   az ad signed-in-user show --query id (principal id, as the docs use it):
#     https://learn.microsoft.com/en-us/cli/azure/ad/signed-in-user
#     https://learn.microsoft.com/en-us/azure/aks/identity-bindings
#   role assignments can take up to five minutes to take effect (a 403 right
#   after the assignment means wait, not troubleshoot):
#     https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity
#   sku-capacity 1 is the smallest capacity in any Microsoft example; the docs
#     state no numeric minimum for a Standard deployment (UNVERIFIED minimum):
#     https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/create-resource
set -u -o pipefail

RG="credprox-m52"
DEPLOYMENT="credprox-m52"
ROLE="Cognitive Services OpenAI User"
SCRATCH="${CREDPROX_M52_AOAI_SCRATCH:-/tmp/credprox-m52-aoai}"
# bounded, fixed budgets (no knob): a create that never provisions and a delete
# that never lands must both FAIL the run into the next leg, not hang it.
ACCOUNT_WAIT_SECONDS=300
GROUP_GONE_WAIT_SECONDS=300

die() { echo "ERROR: $*" >&2; exit 1; }
az_err_code() {
    # From az stderr on stdin print ONLY the error code: the token after
    # "Code:", or the word inside "(...)" when the CLI used the paren shape;
    # when neither shape is present say so - never echo anything from the
    # message body, which can carry resource ids and principals. LC_ALL=C and
    # grep -a: az can print odd bytes, and grep's binary-file-match echo
    # would itself be a leak path.
    local err code=""
    err="$(cat)"
    code="$(printf '%s' "$err" | LC_ALL=C tr -d '\r' \
        | LC_ALL=C grep -aoE 'Code:[[:space:]]*[A-Za-z]+' | head -n 1 | sed 's/^Code:[[:space:]]*//')" || code=""
    if [ -z "$code" ]; then
        code="$(printf '%s' "$err" | LC_ALL=C grep -aoE '\([A-Za-z]+\)' | head -n 1 | tr -d '()')" || code=""
    fi
    [ -n "$code" ] || code="unrecognized, details suppressed"
    printf '%s\n' "$code"
}
az_write() {
    # Run one az WRITE command; on failure die with the given prefix plus az's
    # error code and nothing else. Stdout is dropped like before: a success
    # body carries ids, and every write here is decided by its read-back, not
    # by the verb's own printout.
    local prefix="$1" err
    shift
    if err="$( "$@" 2>&1 >/dev/null )"; then
        return 0
    fi
    die "$prefix (az error code: $(printf '%s' "$err" | az_err_code))"
}

require_signed_in() {
    command -v az >/dev/null 2>&1 || die "az CLI not on PATH (the live run needs the owner's az login)"
    az account get-access-token >/dev/null 2>&1 || die "no active az login (run: az login)"
}

require_names() {
    local v
    for v in AZURE_OPENAI_LOCATION AZURE_OPENAI_MODEL AZURE_OPENAI_MODEL_VERSION AZURE_OPENAI_SKU AZURE_OPENAI_DEPLOYMENT_SKU; do
        [ -n "${!v:-}" ] || die "$v is not set - the run names location, model, version, account SKU and deployment SKU; nothing here is remembered"
    done
}

verb="${1:-}"

case "$verb" in
    --dry-run)
        require_signed_in
        echo "DRY-RUN live-m52-aoai.sh create would run, in order (resource group name fixed, account name suffixed - the account name and its DNS subdomain are GLOBAL namespaces):"
        echo "  az cognitiveservices model list --location \$AZURE_OPENAI_LOCATION (read-only; a name+version the catalog answers Deprecating or Deprecated refuses the run before any write)"
        echo "  az group create --name $RG --location \$AZURE_OPENAI_LOCATION"
        echo "  az cognitiveservices account create --name <account> -g $RG -l \$AZURE_OPENAI_LOCATION --kind OpenAI --sku \$AZURE_OPENAI_SKU --custom-domain <account> --yes"
        echo "  poll az cognitiveservices account show --query properties.provisioningState (up to ${ACCOUNT_WAIT_SECONDS}s) until Succeeded"
        echo "  az resource update --ids <account resource id> --set properties.disableLocalAuth=true"
        echo "  poll az cognitiveservices account show --query properties.provisioningState again (up to ${ACCOUNT_WAIT_SECONDS}s) until Succeeded - the update can re-provision the account"
        echo "  read-back: az cognitiveservices account show --query properties.disableLocalAuth is true"
        echo "  az cognitiveservices account deployment create -g $RG -n <account> --deployment-name $DEPLOYMENT --model-name \$AZURE_OPENAI_MODEL --model-version \$AZURE_OPENAI_MODEL_VERSION --model-format OpenAI --sku-name \$AZURE_OPENAI_DEPLOYMENT_SKU --sku-capacity 1"
        echo "  read-back: az cognitiveservices account deployment show names the deployment"
        echo "  az ad signed-in-user show --query id (principal id captured, never printed)"
        echo "  az role assignment create --role \"$ROLE\" --assignee-object-id <principal> --assignee-principal-type User --scope <account resource id>"
        echo "  read-back: az role assignment list --scope <account id> --role \"$ROLE\" has length 1"
        echo "  handoff: rg/account/location/endpoint/deployment names into $SCRATCH at mode 600 (names only; ids and endpoints never printed)"
        echo "DRY-RUN destroy would run:"
        echo "  az group delete --name $RG --yes --no-wait, then poll az group exists (up to ${GROUP_GONE_WAIT_SECONDS}s) for false"
        echo "  az cognitiveservices account purge --location <from location.txt> --resource-group $RG --name <account>; read-back: poll az cognitiveservices account list-deleted every 5s until the name is absent (budget \$CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS, default 300, shape-checked before any write) - clean / still-listed / could-not-verify / not-attempted, only clean passes (the read-back, not the verb, is the verdict)"
        echo "  read-back: role assignments at the account scope are 0 or the scope is gone; an unresolved account prints SKIPPED - NOT a confirmed zero"
        echo "  rm -rf $SCRATCH only when every read-back confirmed clean - a failed or skipped read-back RETAINS the handoff for a retry (scripts/live-run.sh azureopenai destroy exports the five names a bare re-run needs); the exit code reflects the read-backs"
        ;;
    create)
        require_signed_in
        require_names
        # One leg at a time: ANY handoff file present means a create is or was
        # in flight - an interrupted run leaves SOME files and not others, and
        # writing over even one of them would orphan that run's resources with
        # no recorded names. The old guard watched only the last file written;
        # refuse on the first of the five found, BEFORE any az write.
        for stale in rg.txt account.txt location.txt deployment.txt endpoint.txt; do
            if [ -f "$SCRATCH/$stale" ]; then
                die "a run-created handoff already exists under $SCRATCH (scratch has $stale) - another azureopenai leg is or was in flight; run one vendor at a time, destroy before the next, or remove the stale handoff only after confirming no live leg is running"
            fi
        done
        # Live run 3 proved the model-version catalog is a moving target: the
        # named version had gone Deprecating in the region and Azure refused
        # the deployment create (az error code: ServiceModelDeprecating) - only
        # after the group and the account were created. The catalog read is
        # read-only and needs no account, so consult it BEFORE any write and
        # refuse a Deprecating/Deprecated pick at zero cost. The query answers
        # the lifecycleStatus of exactly the named name+version; an empty
        # answer - name not catalogued, or the read failed - is NOT a refusal,
        # Azure still decides those at deployment create, as it always did.
        model_lifecycle="$(az cognitiveservices model list --location "$AZURE_OPENAI_LOCATION" \
            --query "[?kind=='OpenAI' && model.name=='$AZURE_OPENAI_MODEL' && model.version=='$AZURE_OPENAI_MODEL_VERSION'].model.lifecycleStatus | [0]" \
            -o tsv 2>/dev/null)" || model_lifecycle=""
        case "$(printf '%s' "$model_lifecycle" | tr '[:upper:]' '[:lower:]')" in
            deprecating|deprecated)
                die "model '$AZURE_OPENAI_MODEL' version '$AZURE_OPENAI_MODEL_VERSION' is catalogued as '$model_lifecycle' in $AZURE_OPENAI_LOCATION - Azure refuses new deployments of it (live run 3 died at exactly that refusal after creating the account); pick a version the catalog answers GenerallyAvailable (az cognitiveservices model list --location $AZURE_OPENAI_LOCATION) and re-run - nothing was created" ;;
        esac
        # Owner safety: the fixed group name must be FREE. A pre-existing group
        # of that name is not ours - this run creates its own group and this
        # script never deletes a group it did not create. The refusal names the
        # group and says how to clear it BY HAND; the person confirms the group
        # holds only credprox-m52 resources, then removes it themselves.
        pre_exists="$(az group exists --name "$RG" -o tsv 2>/dev/null | tr '[:upper:]' '[:lower:]')"
        [ "$pre_exists" != "true" ] \
            || die "resource group $RG already exists - this run will never touch a group it did not create. If it is a leftover from an earlier run whose handoff was lost, confirm by hand that it holds only $RG resources, then remove it yourself (az group delete --name $RG --yes); re-run create afterwards"
        mkdir -p "$SCRATCH" && chmod 700 "$SCRATCH"
        # Account name = fixed prefix + 6 random hex: the name AND its DNS
        # subdomain are global namespaces, so a fixed name could be permanently
        # taken. The suffix is a name, not a secret; it lands in scratch and the
        # log, and destroy reads it back from there.
        ACCT="credprox-m52-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
        printf '%s\n' "$ACCT" > "$SCRATCH/account.txt"; chmod 600 "$SCRATCH/account.txt"
        # Every az WRITE goes through az_write: stdout to /dev/null (the
        # returned objects carry subscription and principal GUIDs that must
        # never reach the log); on failure stderr is captured and the step dies
        # with the step name plus the az error CODE only - never the message
        # body, which can carry ids too.
        az_write "resource group create failed" \
            az group create --name "$RG" --location "$AZURE_OPENAI_LOCATION"
        # rg.txt rides ONLY a group create that succeeded on a name we had just
        # seen free: a recorded group is by construction a group this run made.
        printf '%s\n' "$RG" > "$SCRATCH/rg.txt"; chmod 600 "$SCRATCH/rg.txt"
        # location.txt rides the same success as rg.txt: destroy scopes the purge
        # from this record, so a retry never depends on an exported environment
        # to know where the account lived.
        printf '%s\n' "$AZURE_OPENAI_LOCATION" > "$SCRATCH/location.txt"; chmod 600 "$SCRATCH/location.txt"
        az_write "account create failed" \
            az cognitiveservices account create --name "$ACCT" --resource-group "$RG" \
            --location "$AZURE_OPENAI_LOCATION" --kind OpenAI --sku "$AZURE_OPENAI_SKU" \
            --custom-domain "$ACCT" --yes
        # provisioningState enum (docs): Accepted, Creating, Deleting, Moving,
        # Failed, Succeeded, ResolvingDNS - anything Failed/Deleting now is fatal;
        # the rest keep polling until the bound.
        start="$(date +%s)"
        while :; do
            state="$(az cognitiveservices account show --name "$ACCT" --resource-group "$RG" \
                --query properties.provisioningState -o tsv 2>/dev/null)" || state=""
            case "$state" in
                Succeeded) break ;;
                Failed|Deleting) die "read-back: account provisioningState is $state" ;;
            esac
            now="$(date +%s)"
            [ $((now - start)) -lt "$ACCOUNT_WAIT_SECONDS" ] \
                || die "read-back: account provisioningState never reached Succeeded within ${ACCOUNT_WAIT_SECONDS}s (last: ${state:-unknown})"
            sleep 5
        done
        # Live run 1 proved --api-properties does NOT set this property (it lands
        # on properties.apiProperties), so set the real one with the generic ARM
        # PATCH after provisioning succeeded. Live run 2 then failed on the very
        # next call, deployment create, with no reason printed. Leading
        # hypothesis, NOT established: the PATCH starts a new provisioning and
        # the deployment create hit the account while it was still Updating.
        # Re-poll provisioningState after the PATCH, with the same bound as the
        # create poll, before anything else touches the account; the error-code
        # reporting on writes is what will confirm or clear this next run.
        ACCT_ID="$(az cognitiveservices account show --name "$ACCT" --resource-group "$RG" \
            --query id -o tsv 2>/dev/null)"
        [ -n "$ACCT_ID" ] || die "read-back: the created account returned no resource id"
        az_write "local-auth disable failed (az resource update); no deployment was created" \
            az resource update --ids "$ACCT_ID" --set properties.disableLocalAuth=true
        # Same poll shape and bound as after create: the PATCH can leave the
        # account Updating, and a deployment create or a property read during
        # that window is what live run 2 collided with. Failed/Deleting stay
        # fatal; the disableLocalAuth read-back after this stays the decider.
        start="$(date +%s)"
        while :; do
            state="$(az cognitiveservices account show --name "$ACCT" --resource-group "$RG" \
                --query properties.provisioningState -o tsv 2>/dev/null)" || state=""
            case "$state" in
                Succeeded) break ;;
                Failed|Deleting) die "read-back: account provisioningState is $state after the local-auth update" ;;
            esac
            now="$(date +%s)"
            [ $((now - start)) -lt "$ACCOUNT_WAIT_SECONDS" ] \
                || die "read-back: account provisioningState never reached Succeeded after the local-auth update within ${ACCOUNT_WAIT_SECONDS}s (last: ${state:-unknown})"
            sleep 5
        done
        # az prints Python's True for the JSON boolean; compare normalised.
        local_auth="$(az cognitiveservices account show --name "$ACCT" --resource-group "$RG" \
            --query properties.disableLocalAuth -o tsv 2>/dev/null | tr '[:upper:]' '[:lower:]')"
        [ "$local_auth" = "true" ] \
            || die "read-back: local (key) auth is not disabled on the created account (disableLocalAuth read as '${local_auth:-empty}')"
        az_write "deployment create failed" \
            az cognitiveservices account deployment create --resource-group "$RG" --name "$ACCT" \
            --deployment-name "$DEPLOYMENT" --model-name "$AZURE_OPENAI_MODEL" \
            --model-version "$AZURE_OPENAI_MODEL_VERSION" --model-format OpenAI \
            --sku-name "$AZURE_OPENAI_DEPLOYMENT_SKU" --sku-capacity 1
        az cognitiveservices account deployment show --resource-group "$RG" --name "$ACCT" \
            --deployment-name "$DEPLOYMENT" >/dev/null 2>&1 \
            || die "read-back: the created deployment is not listed"
        PRINCIPAL="$(az ad signed-in-user show --query id -o tsv 2>/dev/null)"
        [ -n "$PRINCIPAL" ] || die "the signed-in user's object id could not be resolved (az ad signed-in-user show)"
        SCOPE="$ACCT_ID"
        az_write "role assignment create failed" \
            az role assignment create --role "$ROLE" --assignee-object-id "$PRINCIPAL" \
            --assignee-principal-type User --scope "$SCOPE"
        role_count="$(az role assignment list --scope "$SCOPE" --role "$ROLE" \
            --query "length(@)" -o tsv 2>/dev/null)"
        [ "$role_count" = "1" ] 2>/dev/null \
            || die "read-back: expected exactly 1 role assignment at the account scope (found '${role_count:-none}')"
        ENDPOINT="$(az cognitiveservices account show --name "$ACCT" --resource-group "$RG" \
            --query properties.endpoint -o tsv 2>/dev/null)"
        ENDPOINT="${ENDPOINT%/}"
        [ -n "$ENDPOINT" ] || die "read-back: the created account returned no endpoint"
        # The handoff the runner exports from: names only, mode 600. endpoint.txt
        # last - its existence is the refusal guard above.
        printf '%s\n' "$DEPLOYMENT" > "$SCRATCH/deployment.txt"; chmod 600 "$SCRATCH/deployment.txt"
        printf '%s\n' "$ENDPOINT" > "$SCRATCH/endpoint.txt"; chmod 600 "$SCRATCH/endpoint.txt"
        echo "OK live-m52-aoai create: resource group 1, account 1 (provisioningState Succeeded, disableLocalAuth set and read back true), deployment 1 ($DEPLOYMENT, capacity 1), role assignment 1 ('$ROLE' at the account scope); handoff names in $SCRATCH (no ids or keys printed)"
        ;;
    destroy)
        require_signed_in
        # The recorded group ONLY - never the fixed name as a guess. A run that
        # never recorded a group never confirmed creating one; deleting a
        # same-named group the run did not make is out of the question.
        RG_LEFT=""
        [ -f "$SCRATCH/rg.txt" ] && RG_LEFT="$(tr -d '\n' < "$SCRATCH/rg.txt")"
        ACCT_LEFT=""
        [ -f "$SCRATCH/account.txt" ] && ACCT_LEFT="$(tr -d '\n' < "$SCRATCH/account.txt")"
        LOC_LEFT=""
        [ -f "$SCRATCH/location.txt" ] && LOC_LEFT="$(tr -d '\n' < "$SCRATCH/location.txt")"
        # Guards hoisted to the top of destroy, BEFORE any az write (only the signed-in probe precedes them): a bad
        # purge budget must fail the whole destroy up front, not after the group
        # is already deleted; and a handoff that records a group and an account
        # but no location cannot scope the purge - die and retain the scratch,
        # having issued nothing.
        # '-' not ':-': the default must cover UNSET only. An explicitly empty
        # value is a caller that meant to set a budget and set nothing - the
        # '' arm below can only bite when '' survives to the case word, which
        # ':-' made impossible by turning it into 300.
        case "${CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS-300}" in
            ''|*[!0-9]*|0|0*|???????*)
                die "CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits" ;;
        esac
        if [ -n "$RG_LEFT" ] && [ -n "$ACCT_LEFT" ] && [ -z "$LOC_LEFT" ]; then
            die "location.txt is missing under $SCRATCH although rg.txt and account.txt are present - destroy cannot scope the purge without the location this run recorded; no az write has been issued and the scratch is retained. If this handoff predates the recorded location, destroy a clean run first; writing the file by hand needs the exact creation location confirmed by hand"
        fi
        SCOPE=""
        if [ -n "$ACCT_LEFT" ] && [ -n "$RG_LEFT" ]; then
            # captured BEFORE the delete: after the group is gone the id cannot be
            # re-read, and the zero-check needs the scope it was assigned at.
            SCOPE="$(az cognitiveservices account show --name "$ACCT_LEFT" --resource-group "$RG_LEFT" \
                --query id -o tsv 2>/dev/null)" || SCOPE=""
        fi
        group_gone=0
        if [ -z "$RG_LEFT" ]; then
            echo "SKIPPED: resource-group read-back (no rg.txt under $SCRATCH - destroy will never delete a group this run did not record making); this is NOT a confirmed deletion"
        else
            exists="$(az group exists --name "$RG_LEFT" -o tsv 2>/dev/null | tr '[:upper:]' '[:lower:]')"
            if [ "$exists" != "false" ]; then
                az_write "resource group delete failed" \
                    az group delete --name "$RG_LEFT" --yes --no-wait
            fi
            start="$(date +%s)"
            gone=""
            while :; do
                gone="$(az group exists --name "$RG_LEFT" -o tsv 2>/dev/null | tr '[:upper:]' '[:lower:]')"
                [ "$gone" = "false" ] && break
                now="$(date +%s)"
                [ $((now - start)) -lt "$GROUP_GONE_WAIT_SECONDS" ] || break
                sleep 10
            done
            [ "$gone" = "false" ] && group_gone=1
        fi
        # Purge rides a group that was confirmed gone: a deleted Cognitive
        # Services account is soft-deleted and keeps its name (and DNS
        # subdomain) reserved, so a later create could collide with a resource
        # nobody can see. Purge the recorded account, then READ BACK the
        # soft-deleted list: the verb's exit is never the verdict (a never-
        # created account makes it error), only the read-back decides. Purge
        # settles ASYNCHRONOUSLY - live run 1 observed the name still listed at
        # destroy time and absent from a hand re-read about three minutes later
        # (one observation, no documented bound: UNVERIFIED) - so the read-back
        # polls, bounded, until the name goes absent. Three verdicts, never two:
        #   absent            - a read said zero: clean.
        #   still-listed      - a read said nonzero and the deadline expired.
        #   could-not-verify  - the list read never answered cleanly (it errored
        #                       for the whole budget): an unanswered question
        #                       must never borrow the clean verdict's exit.
        # Only absent passes; the other two fail the destroy and retain the
        # scratch exactly as a listed leftover does.
        # not-attempted is the honest initial state: when the block below
        # never runs (no recorded group, or the group never confirmed gone)
        # the FAILED line must not print a verdict word this destroy did not earn.
        purge_state=not-attempted
        if [ "$group_gone" = "1" ] && [ -n "$RG_LEFT" ] && [ -n "$ACCT_LEFT" ]; then
            # the verb's error is NOT the verdict (a never-created account makes
            # purge error as a matter of course) - but it is worth naming the
            # code, never the body, so a real breakage is not silently swallowed:
            purge_err="$(az cognitiveservices account purge --location "$LOC_LEFT" \
                --resource-group "$RG_LEFT" --name "$ACCT_LEFT" 2>&1 >/dev/null)" \
                || echo "NOTE: the purge verb reported an error (az error code: $(printf '%s' "$purge_err" | az_err_code)); the read-back, not the verb, is the verdict" >&2
            purge_wait="${CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS:-300}"
            start="$(date +%s)"
            deadline=$((start + purge_wait))
            purge_state=could-not-verify
            while :; do
                # live run 2 proof: list-deleted takes NO location/scope argument
                # (rc 2 unrecognized arguments) - the name filter is the exact one.
                if still="$(az cognitiveservices account list-deleted \
                    --query "[?name=='$ACCT_LEFT'] | length(@)" -o tsv 2>/dev/null)"; then
                    if [ "$still" = "0" ] 2>/dev/null; then
                        purge_state=absent
                        break
                    fi
                    purge_state=still-listed
                else
                    purge_state=could-not-verify
                fi
                now="$(date +%s)"
                [ "$now" -lt "$deadline" ] || break
                sleep 5
            done
            if [ "$purge_state" != "absent" ]; then
                echo "purge read-back ended as ${purge_state}: polled list-deleted every 5s with a deadline of ${purge_wait}s from $(date -u -d "@${start}" +%H:%M:%SZ)" >&2
            fi
        fi
        purge_ok=0
        [ "$purge_state" = "absent" ] && purge_ok=1
        purge_verdict="$purge_state"
        [ "$purge_ok" = "1" ] && purge_verdict=clean
        role_zero=1
        if [ -z "$SCOPE" ]; then
            echo "SKIPPED: role-assignment read-back (the run's account scope could not be resolved - a name was recorded but the account was already unreachable); this is NOT a confirmed zero"
        else
            left="$(az role assignment list --scope "$SCOPE" --role "$ROLE" \
                --query "length(@)" -o tsv 2>/dev/null)"
            # A deleted scope answers either with an empty list or an error - both
            # mean nothing is assigned there any more; only a real positive count
            # fails (the post-delete shape is UNVERIFIED in the docs, so both
            # zero-shapes are accepted and the canned test pins both arms).
            [ "$left" = "0" ] 2>/dev/null || [ -z "$left" ] || role_zero=0
        fi
        if [ "$group_gone" != "1" ] || [ "$purge_ok" != "1" ] || [ "$role_zero" != "1" ]; then
            echo "DESTROY-READBACK FAILED: resource group gone=$group_gone deleted account purge=$purge_verdict role assignments zero=$role_zero (1 = clean) - leftovers remain" >&2
            echo "the scratch handoff is RETAINED under $SCRATCH - retry with scripts/live-run.sh azureopenai destroy (it exports the run names from the central live.env; a bare re-run of this script works too now - the group, account and purge location are read back from this scratch, not from the environment); the recorded names are what let the retry name and confirm what it cleans" >&2
            exit 1
        fi
        if [ -z "$SCOPE" ]; then
            # exit stays clean (the group itself is confirmed gone) but a
            # skipped read-back is not a confirmed one: keep the handoff so a
            # later run can finish what this one could not measure.
            echo "the scratch handoff is RETAINED under $SCRATCH - the role read-back was skipped, so a retry (scripts/live-run.sh azureopenai destroy, or this script bare - it reads the group, account and location back from this scratch) can confirm what this run could not"
            exit 0
        fi
        # scratch goes only when every read-back CONFIRMED clean:
        rm -rf "$SCRATCH"
        echo "OK live-m52-aoai destroy: resource group gone, deleted account purged (absent from the soft-deleted list), role assignments at the account scope 0 (or the scope is gone), scratch removed"
        ;;
    *)
        echo "usage: live-m52-aoai.sh create|destroy|--dry-run" >&2
        exit 2
        ;;
esac
