#!/usr/bin/env bash
# M46 unit 3: the Entra app lifecycle for the MicrosoftGraph live vendor.
#   create   - one app registration (credprox-m46-graph) with NO application
#              permission and no admin consent (owner decision 2026-11-22: the
#              live cell proves Graph's own 403 to an app token that holds no
#              permission, so the run grants nothing), a service principal, and
#              one client secret piped straight to the scratch dir - the value
#              never prints, never enters argv of any later step, and never
#              leaves the machine.
#   destroy  - deletes the app (the SP goes with it), read-back proves ZERO
#              apps and service principals of that display name, and the exit
#              code reflects the read-back (the destroy-r2 discipline: a
#              script that exits 0 regardless makes the caller's OK marker
#              a lie).
#   --dry-run- prints the plan; touches nothing.
#
# Only a seat's LEAD runs create/destroy against the real tenant; the read
# verbs (show/list) are fine anywhere. The run grants nothing, so no tenant
# fact needs resolving: neither the Graph service-principal id nor an app-role
# id is fetched or needed.
#
# Offline contract test (GraphAppScriptTests): shadow a stub az at the front of
# PATH and point CREDPROX_M46_SCRATCH at a temp dir; destroy's read-back logic
# must fail its own exit code when the canned output still shows the app.
#
# Scratch: $CREDPROX_M46_SCRATCH (default /tmp/credprox-m46-graph), mode 700;
# client-id.txt + client-secret.txt (mode 600) are the handoff to live-run.sh.
set -u -o pipefail

APP_NAME="credprox-m46-graph"
SCRATCH="${CREDPROX_M46_SCRATCH:-/tmp/credprox-m46-graph}"

die() { echo "ERROR: $*" >&2; exit 1; }

require_signed_in() {
    command -v az >/dev/null 2>&1 || die "az CLI not on PATH (the live run needs the owner's az login)"
    az account get-access-token >/dev/null 2>&1 || die "no active az login (run: az login)"
}

verb="${1:-}"

case "$verb" in
    --dry-run)
        require_signed_in
        echo "DRY-RUN live-graph-app.sh create would run, in order:"
        echo "  az ad app create --display-name $APP_NAME (no permissions requested)"
        echo "  az ad sp create --id <new app id>"
        echo "  az ad app credential reset --append -> $SCRATCH/client-secret.txt (piped, never printed)"
        echo "  read-back: at least one passwordCredential"
        echo "DRY-RUN destroy would run:"
        echo "  az ad app delete per listed app of this display name"
        echo "  read-back: app list count 0 and service-principal list count 0; exit reflects the read-back"
        ;;
    create)
        require_signed_in
        mkdir -p "$SCRATCH" && chmod 700 "$SCRATCH"
        APP_ID="$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)" \
            || die "app create failed"
        [ -n "$APP_ID" ] || die "app create returned no appId"
        # SPs are not auto-provisioned in this tenant (M26 finding):
        az ad sp create --id "$APP_ID" >/dev/null || die "service-principal create failed"
        # No requiredResourceAccess PATCH and no admin-consent here, by design
        # (owner decision 2026-11-22): the run-created app holds NO application
        # permission, and the live cell proves Graph's own 403
        # (Authorization_RequestDenied) on a client-credentials request - the
        # absence of any grant is what the live proof needs.
        # The secret pipes straight from the reset into the scratch file:
        az ad app credential reset --id "$APP_ID" --append \
            --end-date "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)" \
            --query password -o tsv > "$SCRATCH/client-secret.txt" || die "credential reset failed"
        [ -s "$SCRATCH/client-secret.txt" ] || die "credential reset produced an empty value"
        chmod 600 "$SCRATCH/client-secret.txt"
        printf '%s\n' "$APP_ID" > "$SCRATCH/client-id.txt"; chmod 600 "$SCRATCH/client-id.txt"
        # Read-back (create side pairs with destroy's): the credential is there:
        CRED_COUNT="$(az ad app show --id "$APP_ID" --query "passwordCredentials | length(@)" -o tsv)"
        [ "$CRED_COUNT" -ge 1 ] 2>/dev/null || die "read-back: expected a passwordCredential on the app, found none"
        echo "OK live-graph-app create: app $APP_NAME created (client id resolved, secret piped to scratch; values not shown)"
        ;;
    destroy)
        require_signed_in
        APP_IDS="$(az ad app list --display-name "$APP_NAME" --query "[].appId" -o tsv)"
        if [ -n "$APP_IDS" ]; then
            while IFS= read -r id; do
                [ -n "$id" ] && az ad app delete --id "$id" >/dev/null || echo "WARN: delete failed for $id" >&2
            done <<< "$APP_IDS"
        fi
        # Read-back: zero apps of this name, and no SP left behind either.
        LEFT="$(az ad app list --display-name "$APP_NAME" --query "length(@)" -o tsv)"
        SP_LEFT="$(az ad sp list --display-name "$APP_NAME" --query "length(@)" -o tsv)"
        rm -rf "$SCRATCH"
        if [ "$LEFT" != "0" ] || [ "$SP_LEFT" != "0" ]; then
            echo "DESTROY-READBACK FAILED: apps left=$LEFT service-principals left=$SP_LEFT" >&2
            exit 1
        fi
        echo "OK live-graph-app destroy: app registrations 0, service principals 0, scratch removed"
        ;;
    *)
        echo "usage: live-graph-app.sh create|destroy|--dry-run" >&2
        exit 2
        ;;
esac
