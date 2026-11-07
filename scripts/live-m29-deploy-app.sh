#!/usr/bin/env bash
# M29 R2.3 deploy the Container App (infra/azure/aca-app-r2.yaml.tmpl -> az
# containerapp create --yaml) AND the battery job (aca-job-r2.yaml.tmpl -> az
# containerapp job create --yaml, G2). Requires the containerapp CLI extension
# - a LOCAL install the plan's gate list names as a prereq; this script checks
# and instructs rather than installing itself.
# Idempotent: existing app/job are updated via `... update --yaml` rather than
# create-failing. The job template needs the app's internal FQDN, so the order
# is fixed: app -> read back properties.configuration.ingress.fqdn -> job.
# Person-present scope; creates/updates only credprox-m29-app/-battery.
set -euo pipefail
RG=credprox-live-test
APP=credprox-m29-app
JOB=credprox-m29-battery
ACR=credproxm29reg
VAULT=credprox-m29-kv

[[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
  || { echo "az sign-in required (person-present)"; exit 1; }
az containerapp -h >/dev/null 2>&1 \
  || { echo "az containerapp command group absent - run: az extension add --name containerapp (local install, person-present)"; exit 1; }
az keyvault show -n "$VAULT" -g "$RG" -o none 2>/dev/null \
  || { echo "vault $VAULT absent - apply infra first"; exit 1; }

REGISTRY=$(az acr show -n "$ACR" -g "$RG" --query loginServer -o tsv)
ENV_ID=$(az resource show -g "$RG" -n credprox-m29-env --resource-type Microsoft.App/managedEnvironments --query id -o tsv)
# Job location follows the ACTUAL environment region (fallback region included).
LOCATION=$(az resource show -g "$RG" -n credprox-m29-env --resource-type Microsoft.App/managedEnvironments --query location -o tsv)
UAI_ID=$(az identity show -n credprox-m29-uai -g "$RG" --query id -o tsv)
# The runtime containers carry their SDK identity pin in env as
# MANAGED_IDENTITY_CLIENT_ID. The env HINT alone does not work inside ACA
# (wire capture, mic-stub: the SDK never appends it to the identity-proxy
# request there) - Program.cs RuntimeIdentity.Credential() threads this value
# through DefaultAzureCredentialOptions.ManagedIdentityClientId, the form that
# reaches the wire. There is NO containers[].identity schema field at any
# served api-version (live GET schema probes 2026-11-06). CLIENT id (public
# identifier), resolved live, never from memory.
UAI_CLIENT_ID=$(az identity show -n credprox-m29-uai -g "$RG" --query clientId -o tsv)
# The PULL identity: kubelet UAI, holds AcrPull at the registry scope; the app
# and the job attach it and select it via configuration.registries[].identity
# (live finding 2026-11-06: env-level identity never activates image pull).
KUBELET_ID=$(az identity show -n credprox-m29-kubelet -g "$RG" --query id -o tsv)
# envsubst renders an unset/empty var as EMPTY STRING silently - a blank
# registries identity would then provision unauthenticated. Refuse instead.
[[ -n "$UAI_ID" && -n "$UAI_CLIENT_ID" && -n "$KUBELET_ID" ]] \
  || { echo "UAI (or its client id) or kubelet identity missing in $RG - apply infra first"; exit 1; }
VAULT_URI=$(az keyvault show -n "$VAULT" -g "$RG" --query properties.vaultUri -o tsv)
# BUILD STAMP (live finding 2026-11-06): re-pushing an UNCHANGED tag leaves the
# rendered template byte-identical, so `update` creates NO new revision and the
# running pods keep serving the PREVIOUS build (deploy run 9 read back green
# while revision --0000001 from run 8 was still the only revision). Stamp the
# tag's CURRENT digest (resolved live; content hash, public identifier, not
# secret material) into every container: any new push changes the spec -> a new
# revision is forced -> a fresh pull is guaranteed, and the read-backs below
# prove stamp == registry current AND the revision actually bumped.
IMAGE_DIGEST=$(az acr repository show -n "$ACR" --image credprox-m29:latest --query digest -o tsv 2>/dev/null) || true
[[ "$IMAGE_DIGEST" == sha256:* ]] \
  || { echo "image credprox-m29:latest absent/malformed in $ACR - run the docker build+push step first"; exit 1; }
DEPLOY_IMAGE_DIGEST="${IMAGE_DIGEST:7:12}"

# Non-secret wiring material (names only in evidence; read via tsv - both are
# created as SINGLE-LINE secrets by live-m29-material.sh, so tsv is byte-safe):
CALLER_HASH=$(az keyvault secret show --vault-name "$VAULT" --name 'CredProxTest--caller-key-hash' --query value -o tsv 2>/dev/null) || true
CA_B64=$(az keyvault secret show --vault-name "$VAULT" --name 'CredProxTest--mtls-ca-b64' --query value -o tsv 2>/dev/null) || true
[[ -n "$CALLER_HASH" && "$CALLER_HASH" == sha256:* ]] \
  || { echo "CredProxTest--caller-key-hash absent/malformed - run scripts/live-m29-material.sh create first"; exit 1; }
[[ -n "$CA_B64" ]] \
  || { echo "CredProxTest--mtls-ca-b64 absent - run scripts/live-m29-material.sh create first"; exit 1; }

Y=$(mktemp /tmp/credprox-m29-app.XXXXXX.yaml)
J=$(mktemp /tmp/credprox-m29-job.XXXXXX.yaml)
trap 'rm -f "$Y" "$J"' EXIT
cd "$(dirname "$0")/.."
export REGISTRY ENV_ID UAI_ID UAI_CLIENT_ID KUBELET_ID VAULT_URI CALLER_HASH CA_B64 LOCATION DEPLOY_IMAGE_DIGEST
envsubst < infra/azure/aca-app-r2.yaml.tmpl > "$Y"

# Documented identity-pull pattern: ATTACH the identities BEFORE the spec
# that selects one lands. The --yaml path does not carry
# userAssignedIdentities reliably (live finding 2026-11-06), so identity is
# NOT in the template and this assign is the single attach point. Idempotent.
if az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null; then
  az containerapp identity assign -n "$APP" -g "$RG" \
    --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
  az containerapp update -n "$APP" -g "$RG" --yaml "$Y" -o none
  echo "updated $APP"
else
  # First provisioning pass: registries[].identity is still dangling during
  # create (the RP tolerates the resource; its first revision may fail the
  # pull). Attach, then land the spec once more - the template now changes
  # against a failed-revision state and provisions WITH the identity. A failed
  # create for any OTHER reason surfaces immediately after at `identity
  # assign` (resource absent) and stops the script.
  az containerapp create -n "$APP" -g "$RG" --yaml "$Y" -o none \
    || echo "initial create revision may fail pull - identity attach + spec pass follow"
  echo "created $APP"
  az containerapp identity assign -n "$APP" -g "$RG" \
    --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
  az containerapp update -n "$APP" -g "$RG" --yaml "$Y" -o none
fi
# RUNTIME IDENTITY BINDING lives in the templates (MANAGED_IDENTITY_CLIENT_ID
# env + Program.cs RuntimeIdentity.Credential() threading it through
# DefaultAzureCredentialOptions - the only form that reaches the ACA
# identity-proxy wire; see the mic-stub capture). With 2 UAIs attached and no
# pin, every runtime container dies with ManagedIdentityCredential 400 "Unable
# to load the proper Managed Identity" (live finding 2026-11-06). The
# containers[].identity schema field an earlier fix relied on DOES NOT EXIST at
# any api-version this RP serves (live GET schema probes: 2024-08-02-preview,
# 2025-01-01, 2026-07-01) - PATCHing it 400s "Unknown properties identity in
# ContainerAppContainer".
echo "provisioningState: $(az containerapp show -n "$APP" -g "$RG" --query properties.provisioningState -o tsv)"
echo "runningState:      $(az containerapp show -n "$APP" -g "$RG" --query properties.runningState -o tsv)"
echo "identity:          $(az containerapp show -n "$APP" -g "$RG" --query identity.type -o tsv) (expected UserAssigned)"
echo "pull path (app):   kubelet identity selected: $(az containerapp show -n "$APP" -g "$RG" --query "properties.configuration.registries[0].identity | ends_with(@, 'credprox-m29-kubelet')" -o tsv) (expected True); identities attached: $(az containerapp show -n "$APP" -g "$RG" --query 'length(identity.userAssignedIdentities)' -o tsv) (expected 2)"
BOUND_APP=$(az containerapp show -n "$APP" -g "$RG" --query "length(properties.template.containers[?contains(env[*].name, 'MANAGED_IDENTITY_CLIENT_ID')])" -o tsv)
PIN_APP=$(az containerapp show -n "$APP" -g "$RG" --query "properties.template.containers[0].env[?name=='MANAGED_IDENTITY_CLIENT_ID'] | [0].value" -o tsv)
echo "runtime bind (app): env-pinned containers: ${BOUND_APP}/2 (expected 2/2); pin equals runtime UAI client id: $([[ "$PIN_APP" == "$UAI_CLIENT_ID" ]] && echo True || echo False)"
STAMP_P=$(az containerapp show -n "$APP" -g "$RG" --query "properties.template.containers[0].env[?name=='DEPLOY_IMAGE_DIGEST'] | [0].value" -o tsv)
STAMP_C=$(az containerapp show -n "$APP" -g "$RG" --query "properties.template.containers[1].env[?name=='DEPLOY_IMAGE_DIGEST'] | [0].value" -o tsv)
echo "build stamp (app): stamped=${STAMP_P}/${STAMP_C} expected=${DEPLOY_IMAGE_DIGEST} stamp==registry-current: $([[ "$STAMP_P" == "$DEPLOY_IMAGE_DIGEST" && "$STAMP_C" == "$DEPLOY_IMAGE_DIGEST" ]] && echo True || echo False)"
# Freshness witness on the REVISION ITSELF (this CLI model has NO
# properties.currentRevision - a bare show-query on it reads back null):
# newest revision by name + the stamp inside that revision's own spec.
REV_LATEST=$(az containerapp revision list -n "$APP" -g "$RG" --query "sort_by(@, &name)[-1].name" -o tsv)
REV_STAMP=$(az containerapp revision show -n "$APP" -g "$RG" --revision "$REV_LATEST" --query "properties.template.containers[0].env[?name=='DEPLOY_IMAGE_DIGEST'] | [0].value" -o tsv)
echo "revision (app):    ${REV_LATEST}; stamp-in-revision==registry-current: $([[ "$REV_STAMP" == "$DEPLOY_IMAGE_DIGEST" ]] && echo True || echo False) (a stamp change MUST bump the revision; unchanged stamp legitimately reuses it)"

# The battery job runs in-cluster against the app's INTERNAL ingress FQDN
# (read back here - never guessed). G2: replaces the exec-driven battery.
APP_FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
[[ -n "$APP_FQDN" ]] || { echo "internal FQDN unreadable on $APP - ingress absent?"; exit 1; }
export APP_FQDN
envsubst < infra/azure/aca-job-r2.yaml.tmpl > "$J"
if az containerapp job show -n "$JOB" -g "$RG" -o none 2>/dev/null; then
  az containerapp job update -n "$JOB" -g "$RG" --yaml "$J" -o none
  echo "updated $JOB"
else
  az containerapp job create -n "$JOB" -g "$RG" --yaml "$J" -o none
  echo "created $JOB"
fi
# Same identity rule as the app: attach via the CLI (NOT in the job yaml).
# A job pulls only when an execution starts - step 6 starts executions,
# which happens after this script, so attach-after-create is sufficient.
az containerapp job identity assign -n "$JOB" -g "$RG" \
  --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
echo "job provisioningState: $(az containerapp job show -n "$JOB" -g "$RG" --query properties.provisioningState -o tsv)"
echo "job identity:          $(az containerapp job show -n "$JOB" -g "$RG" --query identity.type -o tsv) (expected UserAssigned)"
echo "pull path (job):   kubelet identity selected: $(az containerapp job show -n "$JOB" -g "$RG" --query "properties.configuration.registries[0].identity | ends_with(@, 'credprox-m29-kubelet')" -o tsv) (expected True); identities attached: $(az containerapp job show -n "$JOB" -g "$RG" --query 'length(identity.userAssignedIdentities)' -o tsv) (expected 2)"
BOUND_JOB=$(az containerapp job show -n "$JOB" -g "$RG" --query "length(properties.template.containers[?contains(env[*].name, 'MANAGED_IDENTITY_CLIENT_ID')])" -o tsv)
PIN_JOB=$(az containerapp job show -n "$JOB" -g "$RG" --query "properties.template.containers[0].env[?name=='MANAGED_IDENTITY_CLIENT_ID'] | [0].value" -o tsv)
echo "runtime bind (job): env-pinned containers: ${BOUND_JOB}/1 (expected 1/1); pin equals runtime UAI client id: $([[ "$PIN_JOB" == "$UAI_CLIENT_ID" ]] && echo True || echo False)"
STAMP_B=$(az containerapp job show -n "$JOB" -g "$RG" --query "properties.template.containers[0].env[?name=='DEPLOY_IMAGE_DIGEST'] | [0].value" -o tsv)
echo "build stamp (job): stamped=${STAMP_B} expected=${DEPLOY_IMAGE_DIGEST} stamp==registry-current: $([[ "$STAMP_B" == "$DEPLOY_IMAGE_DIGEST" ]] && echo True || echo False) (executions pull the tag at start; the stamp line in the battery log names the build that ran)"
