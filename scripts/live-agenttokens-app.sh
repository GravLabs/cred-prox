#!/usr/bin/env bash
# M46 unit 3: the Entra app lifecycle for the AgentTokens live vendor.
#   create   - three app registrations for the run:
#                credprox-m46-agents-api  the resource app: exposed API identifier
#                                         api://<its own appId> (set by PATCH
#                                         after create - the tenant's default
#                                         protection policy refuses a fixed
#                                         api:// name at create), plus two
#                                         APPLICATION app roles: docs-read and
#                                         model-call (the sample's model route
#                                         names model-call; a token without it
#                                         is refused 403 before any vendor call
#                                         — live run 2 finding)
#                credprox-m46-agent-mapped     client app whose token the sample
#                                         WILL map (its id goes into TokenClientIds)
#                credprox-m46-agent-unmapped   client app that carries BOTH
#                                         role assignments, exactly like the
#                                         mapped one (lead ruling 2026-11-23:
#                                         with every role present its 401 can
#                                         only come from caller mapping, which
#                                         is the discriminator), but whose id
#                                         is NOT configured — its token must be
#                                         refused for not being a configured
#                                         caller
#              service principals for all three (not auto-provisioned, M26
#              finding), role assignments for both client apps, and one secret
#              per client app piped straight to the scratch dir - no secret value
#              ever prints or enters argv of any later step.
#   destroy  - deletes all three apps (their service principals go with them),
#              read-back proves ZERO apps, service principals and app-role
#              values under those display names, and the exit code reflects the
#              read-back (the destroy-r2 discipline).
#   --dry-run- prints the plan; touches nothing.
#
# Only a seat's LEAD runs create/destroy against the real tenant; read verbs are
# fine anywhere. Tenant facts are resolved from the API at run time.
#
# Offline contract test (AgentTokensScriptTests): shadow a stub az at the front
# of PATH and point CREDPROX_M46_SCRATCH at a temp dir; destroy's read-back logic
# must fail its own exit code when the canned output still shows an app.
#
# Scratch: $CREDPROX_M46_SCRATCH (default /tmp/credprox-m46-agenttokens), mode
# 700; app2-id.txt / app2-secret.txt / app3-id.txt / app3-secret.txt /
# resource-audience.txt (mode 600) are the handoff to the live cell.
set -u -o pipefail

RES_NAME="credprox-m46-agents-api"
MAPPED_NAME="credprox-m46-agent-mapped"
UNMAPPED_NAME="credprox-m46-agent-unmapped"
SCRATCH="${CREDPROX_M46_SCRATCH:-/tmp/credprox-m46-agenttokens}"

die() { echo "ERROR: $*" >&2; exit 1; }

require_signed_in() {
    command -v az >/dev/null 2>&1 || die "az CLI not on PATH (the live run needs the owner's az login)"
    az account get-access-token >/dev/null 2>&1 || die "no active az login (run: az login)"
}

# Create one client app with its SP and one secret piped to <scratch>/<prefix>.
create_client_app() {
    local name="$1" prefix="$2"
    local out app_id
    out="$(az ad app create --display-name "$name" --query "[appId, id]" -o tsv)" \
        || die "client app create failed for $name"
    app_id="$(printf '%s\n' "$out" | head -1)"
    [ -n "$app_id" ] || die "client app create returned no appId for $name"
    az ad sp create --id "$app_id" >/dev/null || die "service-principal create failed for $name"
    az ad app credential reset --id "$app_id" --append \
        --end-date "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)" \
        --query password -o tsv > "$SCRATCH/$prefix-secret.txt" || die "credential reset failed for $name"
    [ -s "$SCRATCH/$prefix-secret.txt" ] || die "credential reset produced an empty value for $name"
    chmod 600 "$SCRATCH/$prefix-secret.txt"
    printf '%s\n' "$app_id" > "$SCRATCH/$prefix-id.txt"; chmod 600 "$SCRATCH/$prefix-id.txt"
    printf '%s\n' "$app_id"
}

# Assign one app role of a resource SP to one client SP (Graph API; az has no
# first-class verb for app-role assignment).
assign_role() {
    local client_sp_id="$1" res_sp_id="$2" role_id="$3"
    az rest --method POST \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$client_sp_id/appRoleAssignments" \
        --body "{\"principalId\":\"$client_sp_id\",\"resourceId\":\"$res_sp_id\",\"appRoleId\":\"$role_id\"}" \
        >/dev/null || die "app-role assignment failed (client SP $client_sp_id)"
}

verb="${1:-}"

case "$verb" in
    --dry-run)
        require_signed_in
        echo "DRY-RUN live-agenttokens-app.sh create would run, in order:"
        echo "  az ad app create --display-name $RES_NAME (NO --identifier-uris: a fixed api:// name is refused by the tenant's default protection policy)"
        echo "  az ad sp create --id <resource app id>"
        echo "  az rest PATCH applications/<resource obj id> identifierUris=[api://<resource appId>] (the one form every tenant accepts)"
        echo "  az rest PATCH applications/<resource obj id> appRoles=[{value:docs-read,type Application},{value:model-call,type Application}]"
        echo "  create client apps $MAPPED_NAME and $UNMAPPED_NAME (SP + one 30-day secret each, piped to $SCRATCH)"
        echo "  az rest POST appRoleAssignments: BOTH client SPs get docs-read AND model-call (identical role sets — the unmapped 401 must come from caller mapping alone)"
        echo "  read-backs: identifierUris exactly [api://<resource appId>], role count 2 with values docs-read model-call, each client SP exactly 2 assignments, both secrets non-empty"
        echo "  handoff: app ids + secrets + resource-audience.txt (the api:// audience) into $SCRATCH at mode 600"
        echo "DRY-RUN destroy would run:"
        echo "  az ad app delete per listed app of the three display names"
        echo "  read-back: app, service-principal and app-role-value counts 0 for all three names; exit reflects the read-back"
        ;;
    create)
        require_signed_in
        mkdir -p "$SCRATCH" && chmod 700 "$SCRATCH"
        # One az-vendor leg at a time: agenttokens and foundrylocal share this
        # scratch and the same three apps, so a handoff already present here
        # means another leg created (or is mid-create of) them. Writing over it
        # would leave that run's apps with no recorded ids and orphan them, so
        # refuse before minting anything.
        if [ -f "$SCRATCH/resource-audience.txt" ]; then
            die "a run-created handoff already exists under $SCRATCH - another az-vendor leg is or was in flight on the shared scratch; run one vendor at a time, destroy before the next, or remove the stale handoff only after confirming no live leg is running"
        fi
        # No --identifier-uris at create: the tenant's default protection policy
        # refuses a fixed api:// name ("All newly added URIs must contain a
        # tenant verified domain, tenant ID, or app ID" — measured 2026-11-22).
        # api://<its own appId> is the one form that always passes, so it is
        # PATCHed on right after create and read back verbatim below.
        RES_OUT="$(az ad app create --display-name "$RES_NAME" \
            --query "[appId, id]" -o tsv)" || die "resource app create failed"
        RES_APP_ID="$(printf '%s\n' "$RES_OUT" | head -1)"
        RES_OBJ_ID="$(printf '%s\n' "$RES_OUT" | tail -1)"
        [ -n "$RES_APP_ID" ] && [ -n "$RES_OBJ_ID" ] || die "resource app create returned no appId/id"
        RES_SP_OUT="$(az ad sp create --id "$RES_APP_ID" --query "[id]" -o tsv)" \
            || die "resource service-principal create failed"
        RES_SP_ID="$(printf '%s\n' "$RES_SP_OUT" | head -1)"
        [ -n "$RES_SP_ID" ] || die "resource service-principal create returned no id"
        # The exposed API identifier is api://<the app's own appId> (see the
        # create note above). az ad app update --set is rejected on the app
        # schema (M26 finding), so this value — like the app role below — goes
        # through the Graph API. A refusal here exits 1 with the create already
        # armed for destroy (live-run.sh arms cleanup before the create).
        az rest --method PATCH \
            --uri "https://graph.microsoft.com/v1.0/applications/$RES_OBJ_ID" \
            --body "{\"identifierUris\":[\"api://$RES_APP_ID\"],\"api\":{\"requestedAccessTokenVersion\":2}}" \
            >/dev/null || die "identifierUris PATCH failed"
        # App-role creation goes through the Graph API (az ad app update --set is
        # rejected on the app schema — M26 finding). The role ids are minted here
        # for this app only; they are not tenant facts being recalled.
        ROLE_ID_DOCS="$(cat /proc/sys/kernel/random/uuid)"
        ROLE_ID_MODEL="$(cat /proc/sys/kernel/random/uuid)"
        az rest --method PATCH \
            --uri "https://graph.microsoft.com/v1.0/applications/$RES_OBJ_ID" \
            --body "{\"appRoles\":[{\"id\":\"$ROLE_ID_DOCS\",\"allowedMemberTypes\":[\"Application\"],\"description\":\"Read docs through the CredProx live test\",\"displayName\":\"docs-read\",\"isEnabled\":true,\"origin\":\"Application\",\"value\":\"docs-read\"},{\"id\":\"$ROLE_ID_MODEL\",\"allowedMemberTypes\":[\"Application\"],\"description\":\"Call the model through the CredProx live test\",\"displayName\":\"model-call\",\"isEnabled\":true,\"origin\":\"Application\",\"value\":\"model-call\"}]}" \
            >/dev/null || die "appRoles PATCH failed"
        # A die inside $( ) only kills the subshell, so re-check the result:
        MAPPED_APP_ID="$(create_client_app "$MAPPED_NAME" app2)"
        [ -n "$MAPPED_APP_ID" ] || die "mapped client app create failed"
        UNMAPPED_APP_ID="$(create_client_app "$UNMAPPED_NAME" app3)"
        [ -n "$UNMAPPED_APP_ID" ] || die "unmapped client app create failed"
        MAPPED_SP_ID="$(az ad sp list --filter "appId eq '$MAPPED_APP_ID'" --query "[0].id" -o tsv)"
        UNMAPPED_SP_ID="$(az ad sp list --filter "appId eq '$UNMAPPED_APP_ID'" --query "[0].id" -o tsv)"
        [ -n "$MAPPED_SP_ID" ] && [ "$MAPPED_SP_ID" != "None" ] || die "mapped client SP not found"
        [ -n "$UNMAPPED_SP_ID" ] && [ "$UNMAPPED_SP_ID" != "None" ] || die "unmapped client SP not found"
        # Both client SPs carry the IDENTICAL role set: the unmapped 401 can then
        # only come from caller mapping, not from a missing role (lead ruling).
        assign_role "$MAPPED_SP_ID" "$RES_SP_ID" "$ROLE_ID_DOCS"
        assign_role "$MAPPED_SP_ID" "$RES_SP_ID" "$ROLE_ID_MODEL"
        assign_role "$UNMAPPED_SP_ID" "$RES_SP_ID" "$ROLE_ID_DOCS"
        assign_role "$UNMAPPED_SP_ID" "$RES_SP_ID" "$ROLE_ID_MODEL"
        # Read-backs (create side pairs with destroy's):
        URI_COUNT="$(az ad app show --id "$RES_APP_ID" --query "identifierUris | length(@)" -o tsv)"
        URI_AUD="$(az ad app show --id "$RES_APP_ID" --query "join(' ', identifierUris)" -o tsv)"
        ROLE_COUNT="$(az ad app show --id "$RES_APP_ID" --query "appRoles | length(@)" -o tsv)"
        ROLE_VALUES="$(az ad app show --id "$RES_APP_ID" --query "join(' ', appRoles[].value)" -o tsv)"
        ASSIGN_2="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MAPPED_SP_ID/appRoleAssignments" \
            --query "value | length(@)" -o tsv)"
        ASSIGN_3="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UNMAPPED_SP_ID/appRoleAssignments" \
            --query "value | length(@)" -o tsv)"
        [ "$URI_COUNT" = "1" ] || die "read-back: expected the api:// identifier on the resource app, found $URI_COUNT"
        # Exact value, not just presence: the PATCH must have landed the app's
        # own appId as the audience, or the live cell would mint tokens against
        # an audience the sample never accepts.
        [ "$URI_AUD" = "api://$RES_APP_ID" ] \
            || die "read-back: resource app identifier is not its own api://<appId> (found $URI_COUNT uri(s))"
        [ "$ROLE_COUNT" = "2" ] || die "read-back: expected 2 app roles on the resource app, found $ROLE_COUNT"
        # Exact role SET, not just the count: the sample's routes name docs-read
        # and model-call; a PATCH that landed a different value would mint tokens
        # the routes refuse, and the count alone would not catch a swapped value.
        # Graph may return appRoles in any order (live run 3 died here when the
        # join came back "model-call docs-read"), so the compare sorts first —
        # a duplicate or a wrong value still misses the exact-string check.
        ROLE_SET="$(printf '%s\n' $ROLE_VALUES | LC_ALL=C sort | paste -sd' ' -)"
        [ "$ROLE_SET" = "docs-read model-call" ] \
            || die "read-back: resource app roles are not exactly docs-read model-call (found: $ROLE_VALUES)"
        [ "$ASSIGN_2" = "2" ] 2>/dev/null || die "read-back: mapped client SP has no role assignment for both roles (found $ASSIGN_2)"
        [ "$ASSIGN_3" = "2" ] 2>/dev/null || die "read-back: unmapped client SP has no role assignment for both roles (found $ASSIGN_3)"
        # v2 access tokens (requestedAccessTokenVersion 2, set with the identifier)
        # carry the v2 issuer the sample's Authority names and the API's client id
        # as aud, so the client id is the audience. The live cell cannot know a
        # run-minted audience ahead of time, so it
        # reads it from the handoff — the same channel as the client secrets.
        printf '%s\n' "$RES_APP_ID" > "$SCRATCH/resource-audience.txt" \
            || die "could not write the audience handoff"
        chmod 600 "$SCRATCH/resource-audience.txt"
        echo "OK live-agenttokens-app create: 3 apps, 3 service principals, 4 app-role assignments (both client SPs: docs-read + model-call), 2 secrets + audience piped to scratch (values not shown)"
        ;;
    destroy)
        require_signed_in
        APP_LEFT_TOTAL=0
        SP_LEFT_TOTAL=0
        ROLE_LEFT_TOTAL=0
        for name in "$RES_NAME" "$MAPPED_NAME" "$UNMAPPED_NAME"; do
            ids="$(az ad app list --display-name "$name" --query "[].appId" -o tsv)"
            if [ -n "$ids" ]; then
                while IFS= read -r id; do
                    [ -n "$id" ] && az ad app delete --id "$id" >/dev/null || echo "WARN: delete failed for $id" >&2
                done <<< "$ids"
            fi
            left="$(az ad app list --display-name "$name" --query "length(@)" -o tsv)"
            sp_left="$(az ad sp list --display-name "$name" --query "length(@)" -o tsv)"
            # An app deleted with its roles leaves no appRoles anywhere; a
            # half-deleted registration would still surface its role values.
            role_left="$(az ad app list --display-name "$name" --query "[].appRoles[].value | length(@)" -o tsv)"
            [ "$left" = "0" ] || APP_LEFT_TOTAL=$((APP_LEFT_TOTAL + left))
            [ "$sp_left" = "0" ] || SP_LEFT_TOTAL=$((SP_LEFT_TOTAL + sp_left))
            [ "$role_left" = "0" ] || ROLE_LEFT_TOTAL=$((ROLE_LEFT_TOTAL + role_left))
        done
        rm -rf "$SCRATCH"
        if [ "$APP_LEFT_TOTAL" != "0" ] || [ "$SP_LEFT_TOTAL" != "0" ] || [ "$ROLE_LEFT_TOTAL" != "0" ]; then
            echo "DESTROY-READBACK FAILED: apps left=$APP_LEFT_TOTAL service-principals left=$SP_LEFT_TOTAL app-role values left=$ROLE_LEFT_TOTAL" >&2
            exit 1
        fi
        echo "OK live-agenttokens-app destroy: app registrations 0, service principals 0, app-role values 0, scratch removed"
        ;;
    *)
        echo "usage: live-agenttokens-app.sh create|destroy|--dry-run" >&2
        exit 2
        ;;
esac
