#!/usr/bin/env bash
# M46 unit 3 ACA lifecycle: apply | push | deploy | verify | destroy | --dry-run.
# One run creates everything the shipped samples/AzureContainerApps needs in
# Azure (RG, vault, identities, ACR, environment, app with the shipped StubApi
# co-located, verify job) and destroy deletes it ALL again - including the
# resource group - with read-backs deciding the exit code.
#
# DISCLOSED DIVERGENCE from the M29 trio (live-infra-destroy-r2.sh keeps the RG
# deliberately, per the plan): the M46 row demands the resource group GONE, so
# destroy deletes the whole group and read-backs `az group exists` -> false,
# failing loudly on true. Everything else mirrors the M29 discipline: sign-in
# and extension gates before any write; vault purge with purge protection
# OMITTED (never false) per the bicep; identity ATTACHED via the CLI before the
# spec that selects it (--yaml does not carry userAssignedIdentities reliably,
# live finding 2026-11-06); the build stamp forces a fresh revision on
# byte-identical re-pushes; ARM deletes are async, so every read-back polls
# (10s x24, the ACR 2-4 min latency finding); secret values travel ONLY through
# scratch files at mode 600 and `--file` uploads - never argv, never printed.
# The job's --mode args ride the rendered yaml (the CLI `--args` limitation
# live-azure-smoke.sh documents applies to mutating args via the CLI, not to
# yaml-rendered templates - aca-job-r2.yaml.tmpl shipped args this way in M29).
#
# Run-manually scope; creates/deletes only credprox-m46-* objects. Live Azure
# steps are the lead's; offline legs run against a canned az on PATH.
# GUID rule: role definition ids and the officer principal id are resolved
# live at apply time (az role definition list --name, az ad signed-in-user);
# nothing here is a remembered GUID.
set -euo pipefail
RG=credprox-m46-aca
VAULT=credprox-m46-kv
APP=credprox-m46-app
JOB=credprox-m46-verify
CAPENV=credprox-m46-env
ACR=credproxm46reg
UAI=credprox-m46-uai
KUBELET=credprox-m46-kubelet
LOC="${CREDPROX_M46_ACA_LOCATION:-eastus}"   # Americas-only (round-2 decision)
SCRATCH="${CREDPROX_M46_ACA_SCRATCH:-/tmp/credprox-m46-aca}"
# Poll cadence caps (live defaults = the round-2 findings: 10s x24 for resource
# deletes at ACR latency, x36 for the RG; verify 8s x120 so the poll outlasts
# the job template's replicaTimeout 900 - the runner stops polling only after
# the job itself can no longer succeed). The canned-az offline cells shrink
# these to seconds; the SHAPES they assert are identical.
ACA_POLL_S="${CREDPROX_M46_ACA_POLL_S:-10}"
ACA_POLL_N="${CREDPROX_M46_ACA_POLL_N:-24}"
ACA_POLL_RG_N="${CREDPROX_M46_ACA_POLL_RG_N:-36}"
ACA_VERIFY_S="${CREDPROX_M46_ACA_VERIFY_POLL_S:-8}"
ACA_VERIFY_N="${CREDPROX_M46_ACA_VERIFY_N:-120}"
IMG_ACA=credprox-m46-aca
IMG_STUB=credprox-m46-stub
IMG_HARNESS=credprox-m46-harness
# Vault material: the sample's two shipped secret refs (bindable CredProx--
# names - both are declared in the sample's appsettings Secrets block, the
# validator contract from the M29 NAMING RULE) + the caller key VALUE under a
# validator-inert CredProxTest-- name: the verify job fetches it directly by
# SecretClient name, so it never needs to be a config key at all.
NAMES=(CredProx--Secrets--demoCallerKeyHash CredProx--Secrets--acme-vendor-key CredProxTest--aca-caller-key)

gate_signin() {
  [[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
    || { echo "az sign-in required (run manually)"; exit 1; }
  az containerapp -h >/dev/null 2>&1 \
    || { echo "az containerapp command group absent - run: az extension add --name containerapp (local install, run manually)"; exit 1; }
}

scratch_file() {  # $1 = path under SCRATCH - created 600, scratch dir 700
  mkdir -p "$SCRATCH"; chmod 700 "$SCRATCH"
  : > "$1"; chmod 600 "$1"
}

digest_of() {  # $1 = repo:tag in ACR - the CURRENT tag digest, resolved live
  az acr repository show -n "$ACR" --image "$1" --query digest -o tsv 2>/dev/null
}

aca_verify_diagnostics() {
  # Diagnose BEFORE destroy erases the app (live finding 2026-11-22: three
  # checks timed out and nothing in the log said why). Both verify poll failure
  # branches call this: the job reporting Failed, AND a wedged terminal status
  # (Stopped/Timeout/Cancelled/Deleting) whose early exit used to skip the why
  # entirely (owner follow-up folded for 0.15.1). Revision health plus the
  # proxy's own console and system lines. Each call site then exits 1, which
  # skips the runner's inline scan; its EXIT trap runs the same scan after the
  # destroys, so everything printed here is scanned too (268d470 check,
  # MEDIUM-1).
  echo "--- diagnostics: app revisions (name health running replicas) ---"
  az containerapp revision list -n "$APP" -g "$RG" \
    --query "[].[name, properties.healthState, properties.runningState, properties.replicas]" -o tsv 2>&1 || true
  echo "--- diagnostics: proxy console (last 40) ---"
  az containerapp logs show -n "$APP" -g "$RG" --container proxy --type console --tail 40 --format text 2>&1 || true
  echo "--- diagnostics: app system events (last 40) ---"
  az containerapp logs show -n "$APP" -g "$RG" --type system --tail 40 --format text 2>&1 || true
}

case "${1:-}" in
--dry-run)
  # The offline print-plan gate: names and steps only, ZERO az invocations -
  # what-if for the bicep set is the lead-run gate (infra/azure/
  # credprox-m46-aca-sub.bicep, az deployment sub what-if).
  echo "plan (no writes performed):"
  echo "  apply   : az group create $RG ($LOC); az deployment group create infra/azure/credprox-m46-aca.bicep" \
    "(vault $VAULT purge-protection omitted, uai $UAI, kubelet $KUBELET, acr $ACR Basic, env $CAPENV Consumption;" \
    "3 RBAC assignments; role-definition ids + officer principal resolved live)"
  echo "  apply   : + vault material - 3 secrets via --file uploads only: ${NAMES[*]} (names only, ever)"
  echo "  push    : docker build (samples/AzureContainerApps, samples/AzureContainerApps/StubApi, tools/aca-live-harness)" \
    "-> $ACR as $IMG_ACA:latest, $IMG_STUB:latest, $IMG_HARNESS:latest; digest read-back per tag"
  echo "  deploy  : envsubst aca-m46-app.yaml.tmpl (2 shipped containers, internal ingress :8080, --urls override);" \
    "identity assign (UAI+kubelet) BEFORE spec; read-backs: pull-path kubelet, 2 identities, stamp==current, revision bumped;" \
    "then aca-m46-job.yaml.tmpl (args via yaml) + job identity assign"
  echo "  verify  : az containerapp job start $JOB; poll status; strip log-routing prefix; C1..C3 + ACACHECK lines decide exit"
  echo "  destroy : app,job -> env -> acr -> vault delete+PURGE (same region) -> identities -> role-assignment read-backs" \
    "(uai/kubelet principals zero) -> az group delete $RG -> poll az group exists == false"
  echo "  scratch : $SCRATCH (700; secret handoffs 600; removed by destroy)"
  ;;

apply)
  gate_signin
  az group create -n "$RG" -l "$LOC" -o none
  echo "rg: $RG ready"
  # Resolved live - never from memory (M26 lesson pinned in the bicep header).
  OFFICER=$(az ad signed-in-user show --query id -o tsv)
  OFFICER_ROLE=$(az role definition list --name 'Key Vault Secrets Officer' --query '[0].name' -o tsv)
  VAULT_USER_ROLE=$(az role definition list --name 'Key Vault Secrets User' --query '[0].name' -o tsv)
  ACR_PULL_ROLE=$(az role definition list --name 'AcrPull' --query '[0].name' -o tsv)
  [[ -n "$OFFICER" && -n "$OFFICER_ROLE" && -n "$VAULT_USER_ROLE" && -n "$ACR_PULL_ROLE" ]] \
    || { echo "principal or role definition unresolved (az output empty) - refusing"; exit 1; }
  cd "$(dirname "$0")/.."
  az deployment group create -g "$RG" --template-file infra/azure/credprox-m46-aca.bicep \
    --parameters mainLocation="$LOC" vaultLocation="$LOC" \
    officerPrincipalId="$OFFICER" officerRoleId="$OFFICER_ROLE" \
    vaultUserRoleDefinitionId="$VAULT_USER_ROLE" acrPullRoleId="$ACR_PULL_ROLE" -o none
  az keyvault show -n "$VAULT" -g "$RG" -o none \
    || { echo "vault $VAULT absent after apply"; exit 1; }
  echo "infra: $(az resource list -g "$RG" --query 'length(@)' -o tsv) resources in $RG (names only here)"
  # fallthrough to material: the vault data-plane step is the same gated verb
  ;&
material)
  gate_signin
  az keyvault show -n "$VAULT" -g "$RG" -o none 2>/dev/null \
    || { echo "vault $VAULT absent - run apply first"; exit 1; }
  D=$(mktemp -d /tmp/credprox-m46-material.XXXXXX)
  trap 'rm -rf "$D"' EXIT
  # Byte hygiene (M26 Phase-4 rule): single-line secrets WITHOUT trailing
  # newline - stored bytes must equal the header value and the hash input.
  openssl rand -hex 24 | tr -d '\n' > "$D/caller.key"
  openssl rand -hex 24 | tr -d '\n' > "$D/vendor.key"
  printf 'sha256:%s' "$(sha256sum "$D/caller.key" | cut -d' ' -f1)" > "$D/caller.hash"
  for n in "${NAMES[@]}"; do echo "preparing $n"; done
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--demoCallerKeyHash' --file "$D/caller.hash" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--acme-vendor-key' --file "$D/vendor.key" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProxTest--aca-caller-key' --file "$D/caller.key" -o none
  # Keep the minted values OUT of the vault-only world: the runner's leak scan
  # needs to know the run's values, so they land in the scratch handoff (600),
  # never on a terminal or in argv.
  scratch_file "$SCRATCH/aca-secrets.env"
  { printf 'ACA_CALLER_KEY=%s\n' "$(cat "$D/caller.key")"; printf 'ACA_VENDOR_KEY=%s\n' "$(cat "$D/vendor.key")"; } \
    > "$SCRATCH/aca-secrets.env"
  echo "material: $(az keyvault secret list --vault-name "$VAULT" --query 'length(@)' -o tsv) secrets present (expected 3); names only in this log; scratch handoff at $SCRATCH/aca-secrets.env (mode 600)"
  ;;

push)
  gate_signin
  LOGIN=$(az acr show -n "$ACR" -g "$RG" --query loginServer -o tsv 2>/dev/null) \
    || { echo "acr $ACR absent - run apply first"; exit 1; }
  # docker push needs registry credentials: az acr login hands docker a short-lived
  # token for this run's own registry (nothing stored beyond docker's credential file)
  az acr login -n "$ACR" >/dev/null 2>&1 || { echo "az acr login to $ACR failed"; exit 1; }
  cd "$(dirname "$0")/.."
  docker build -f samples/AzureContainerApps/Dockerfile -t "$LOGIN/$IMG_ACA:latest" .
  docker build -f samples/AzureContainerApps/StubApi/Dockerfile -t "$LOGIN/$IMG_STUB:latest" .
  docker build -f tools/aca-live-harness/Dockerfile -t "$LOGIN/$IMG_HARNESS:latest" .
  docker push "$LOGIN/$IMG_ACA:latest"
  docker push "$LOGIN/$IMG_STUB:latest"
  docker push "$LOGIN/$IMG_HARNESS:latest"
  # Digest read-back (the M29 pattern): a pushed tag that the registry cannot
  # echo as sha256:* means the push never landed - loud fail, not a stale pull.
  for IMG in "$IMG_ACA" "$IMG_STUB" "$IMG_HARNESS"; do
    DIG=$(digest_of "$IMG:latest") || true
    [[ "$DIG" == sha256:* ]] \
      || { echo "pushed digest read-back mismatched: $IMG:latest absent/malformed in $ACR"; exit 1; }
    echo "pushed: $IMG:latest ${DIG:7:12}"
  done
  ;;

deploy)
  gate_signin
  REGISTRY=$(az acr show -n "$ACR" -g "$RG" --query loginServer -o tsv 2>/dev/null) \
    || { echo "acr $ACR absent - run apply/push first"; exit 1; }
  ENV_ID=$(az resource show -g "$RG" -n "$CAPENV" --resource-type Microsoft.App/managedEnvironments --query id -o tsv)
  LOCATION=$(az resource show -g "$RG" -n "$CAPENV" --resource-type Microsoft.App/managedEnvironments --query location -o tsv)
  UAI_ID=$(az identity show -n "$UAI" -g "$RG" --query id -o tsv)
  # Runtime containers pin the SDK identity via MANAGED_IDENTITY_CLIENT_ID +
  # the harness/sample code threading it through DefaultAzureCredentialOptions
  # - CLIENT id resolved live (public identifier, round-2 wire findings).
  UAI_CLIENT_ID=$(az identity show -n "$UAI" -g "$RG" --query clientId -o tsv)
  KUBELET_ID=$(az identity show -n "$KUBELET" -g "$RG" --query id -o tsv)
  # envsubst renders unset vars as EMPTY STRING silently - a blank registries
  # identity would provision unauthenticated. Refuse instead (M29 guard).
  [[ -n "$REGISTRY" && -n "$ENV_ID" && -n "$LOCATION" && -n "$UAI_ID" && -n "$UAI_CLIENT_ID" && -n "$KUBELET_ID" ]] \
    || { echo "registry/env/identity ids unresolved in $RG - apply first"; exit 1; }
  VAULT_URI=$(az keyvault show -n "$VAULT" -g "$RG" --query properties.vaultUri -o tsv)
  [[ -n "$VAULT_URI" ]] || { echo "vault uri unreadable - apply first"; exit 1; }
  SAMPLE_DIGEST=$(digest_of "$IMG_ACA:latest") || true
  HARNESS_DIGEST=$(digest_of "$IMG_HARNESS:latest") || true
  [[ "$SAMPLE_DIGEST" == sha256:* && "$HARNESS_DIGEST" == sha256:* ]] \
    || { echo "image absent/malformed in $ACR - run the push step first"; exit 1; }
  STUB_DIGEST=$(digest_of "$IMG_STUB:latest") || true
  [[ "$STUB_DIGEST" == sha256:* ]] || { echo "stub image absent in $ACR - run push"; exit 1; }
  Y=$(mktemp /tmp/credprox-m46-app.XXXXXX.yaml)
  J=$(mktemp /tmp/credprox-m46-job.XXXXXX.yaml)
  trap 'rm -f "$Y" "$J"' EXIT
  cd "$(dirname "$0")/.."
  # BUILD STAMP per image (round-2 finding: unchanged tag -> no new revision ->
  # stale pods). The app template carries the SAMPLE digest (its spec changes
  # when the host image changes); the job carries the HARNESS digest.
  DEPLOY_IMAGE_DIGEST="${SAMPLE_DIGEST:7:12}"
  export REGISTRY ENV_ID UAI_CLIENT_ID KUBELET_ID VAULT_URI DEPLOY_IMAGE_DIGEST
  envsubst < infra/azure/aca-m46-app.yaml.tmpl > "$Y"
  [[ -s "$Y" && "$(grep -c '\$[A-Z]' "$Y" || true)" == 0 ]] \
    || { echo "app yaml rendered with unsubstituted tokens - refusing"; exit 1; }
  # ATTACH the identities BEFORE the spec that selects one (single attach
  # point - the yaml carries no identity section, by live finding).
  if az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null; then
    az containerapp identity assign -n "$APP" -g "$RG" --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
    az containerapp update -n "$APP" -g "$RG" --yaml "$Y" -o none
    echo "updated $APP"
  else
    az containerapp create -n "$APP" -g "$RG" --yaml "$Y" -o none \
      || echo "initial create revision may fail pull - identity attach + spec pass follow"
    # A refused spec creates nothing; only a created app may go on to the
    # identity attach (live finding 2026-11-22: a refused yaml printed "created").
    az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null \
      || { echo "create refused: $APP does not exist after create - see the error above"; exit 1; }
    echo "created $APP"
    az containerapp identity assign -n "$APP" -g "$RG" --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
    az containerapp update -n "$APP" -g "$RG" --yaml "$Y" -o none
  fi
  echo "provisioningState: $(az containerapp show -n "$APP" -g "$RG" --query properties.provisioningState -o tsv) (not gated: ARM provisioning is async; verify's job + C-lines are the end-to-end gate)"
  IDTYPE=$(az containerapp show -n "$APP" -g "$RG" --query identity.type -o tsv)
  KSEL=$(az containerapp show -n "$APP" -g "$RG" --query "properties.configuration.registries[0].identity | ends_with(@, '$KUBELET')" -o tsv)
  NCOUNT=$(az containerapp show -n "$APP" -g "$RG" --query 'length(identity.userAssignedIdentities)' -o tsv)
  STAMP_A=$(az containerapp show -n "$APP" -g "$RG" --query "properties.template.containers[0].env[?name=='DEPLOY_IMAGE_DIGEST'] | [0].value" -o tsv)
  echo "identity:          $IDTYPE (expected UserAssigned)"
  echo "pull path (app):   kubelet identity selected: $KSEL (expected true); identities attached: $NCOUNT (expected 2)"
  echo "build stamp (app): stamped=${STAMP_A} expected=${DEPLOY_IMAGE_DIGEST} stamp==registry-current: $([[ "$STAMP_A" == "$DEPLOY_IMAGE_DIGEST" ]] && echo True || echo False)"
  # READ-BACKS DECIDE (row bar): an unattached identity or an unselected pull
  # path makes the NEXT revision fail its image pull - deploy must not walk past
  # a False it just printed. az -o tsv prints a JMESPath boolean in lowercase
  # ("true"), like `az group exists` below (live finding 2026-11-22: a "True"
  # comparison refused a deploy whose read-backs were all correct).
  [[ "$IDTYPE" == "UserAssigned" && "$KSEL" == "true" && "$NCOUNT" == "2" && "$STAMP_A" == "$DEPLOY_IMAGE_DIGEST" ]] \
    || { echo "app identity/pull-path/stamp read-back mismatch - refusing to proceed"; exit 1; }
  REV_LATEST=$(az containerapp revision list -n "$APP" -g "$RG" --query "sort_by(@, &name)[-1].name" -o tsv)
  echo "revision (app):    ${REV_LATEST} (no properties.currentRevision on this CLI; newest-by-name is the witness)"
  APP_FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
  [[ -n "$APP_FQDN" ]] || { echo "internal FQDN unreadable on $APP - ingress absent?"; exit 1; }
  APP_FQDN="${APP_FQDN#https://}"
  DEPLOY_IMAGE_DIGEST="${HARNESS_DIGEST:7:12}"
  export APP_FQDN DEPLOY_IMAGE_DIGEST
  envsubst < infra/azure/aca-m46-job.yaml.tmpl > "$J"
  [[ -s "$J" && "$(grep -c '\$[A-Z]' "$J" || true)" == 0 ]] \
    || { echo "job yaml rendered with unsubstituted tokens - refusing"; exit 1; }
  if az containerapp job show -n "$JOB" -g "$RG" -o none 2>/dev/null; then
    az containerapp job update -n "$JOB" -g "$RG" --yaml "$J" -o none
    echo "updated $JOB"
  else
    az containerapp job create -n "$JOB" -g "$RG" --yaml "$J" -o none
    echo "created $JOB"
  fi
  # A job pulls only when an execution starts - attach after create is sufficient.
  az containerapp job identity assign -n "$JOB" -g "$RG" --user-assigned "$UAI_ID" "$KUBELET_ID" -o none
  JOB_IDTYPE=$(az containerapp job show -n "$JOB" -g "$RG" --query identity.type -o tsv)
  JOB_KSEL=$(az containerapp job show -n "$JOB" -g "$RG" --query "properties.configuration.registries[0].identity | ends_with(@, '$KUBELET')" -o tsv)
  JOB_N=$(az containerapp job show -n "$JOB" -g "$RG" --query 'length(identity.userAssignedIdentities)' -o tsv)
  echo "job identity:          $JOB_IDTYPE (expected UserAssigned)"
  echo "pull path (job):   kubelet identity selected: $JOB_KSEL (expected true); identities attached: $JOB_N (expected 2)"
  [[ "$JOB_IDTYPE" == "UserAssigned" && "$JOB_KSEL" == "true" && "$JOB_N" == "2" ]] \
    || { echo "job identity/pull-path read-back mismatch - verify could not pull"; exit 1; }
  ;;

verify)
  gate_signin
  # Start ONE execution. A start that succeeds but prints no name must NEVER
  # be re-tried (an accepted launch already fired - duplicate witnesses); the
  # name is resolved from the execution list instead (live-azure-smoke.sh rule).
  EXEC=""
  STARTED=0
  for tries in 3 2 1; do
    if EXEC=$(az containerapp job start -g "$RG" -n "$JOB" --query properties.name -o tsv 2>/dev/null); then
      STARTED=1
      break
    fi
    echo "job start refused (attempt $((4-tries))/3) - provisioning op likely active" >&2
    [[ $tries -gt 1 ]] && sleep 20
  done
  [[ $STARTED == 1 ]] || { echo "could not start $JOB"; exit 1; }
  if [[ -z "$EXEC" || "$EXEC" == "None" ]]; then
    sleep 5
    EXEC=$(az containerapp job execution list -g "$RG" -n "$JOB" \
      --query "sort_by(@,&properties.startTime)[-1].name" -o tsv 2>/dev/null)
    [[ -n "$EXEC" ]] || { echo "job start accepted but execution name unresolvable"; exit 1; }
  fi
  STATUS=Unknown
  for _ in $(seq 1 "$ACA_VERIFY_N"); do   # default <=960s > replicaTimeout 900: a slow-but-succeeding job must not read as a runner timeout
    sleep "$ACA_VERIFY_S"
    STATUS=$(az containerapp job execution show -g "$RG" -n "$JOB" --job-execution-name "$EXEC" --query properties.status -o tsv 2>/dev/null) || STATUS=Unknown
    case "$STATUS" in Succeeded|Failed|Stopped|Timeout|Cancelled|Deleting) break ;; esac
  done
  case "$STATUS" in
    Succeeded|Failed) : ;;
    *) echo "job execution $EXEC did not finish (last status: $STATUS)"; aca_verify_diagnostics; exit 1 ;;
  esac
  # Strip the log-routing prefix ("<ts> stdout F ...") or every line-anchored
  # grep silently misses (live finding 2026-11-06).
  LOG=$(az containerapp job logs show -g "$RG" -n "$JOB" --execution "$EXEC" \
    --container acacheck --tail 300 --format text 2>/dev/null \
    | sed -E 's/^[^ ]+ (stdout|stderr) [A-Z] //')
  NPASS=$(printf '%s\n' "$LOG" | grep -cE '^C[0-9]+ PASS ' || true)
  NFAIL=$(printf '%s\n' "$LOG" | grep -cE '^C[0-9]+ FAIL ' || true)
  printf '%s\n' "$LOG" | grep -E '^(acacheck UTC|build:|C[0-9]+ |warn: |error: |ACACHECK )' || true
  if [[ "$STATUS" == Succeeded && "$NPASS" == 3 && "$NFAIL" == 0 ]] \
      && printf '%s\n' "$LOG" | grep -qx 'ACACHECK OK'; then
    # numbers only — the runner's PASS line is built from this and carries no
    # FQDN, tenant or subscription identifier
    echo "OBSERVED 3/3 acacheck checks passed, job Succeeded"
  else
    echo "aca verify: FAIL (status=$STATUS pass=$NPASS fail=$NFAIL)"
    aca_verify_diagnostics
    exit 1
  fi
  ;;

destroy)
  # Idempotent, dependency order, extension-free verbs first (the exit path
  # must never depend on the containerapp extension). Principal ids are read
  # BEFORE the identities go - the role-assignment read-back is by principal.
  UAI_PRIN=$(az identity show -n "$UAI" -g "$RG" --query principalId -o tsv 2>/dev/null) || true
  KUBELET_PRIN=$(az identity show -n "$KUBELET" -g "$RG" --query principalId -o tsv 2>/dev/null) || true
  az resource delete -g "$RG" -n "$APP" --resource-type Microsoft.App/containerApps -o none 2>/dev/null || true
  az resource delete -g "$RG" -n "$JOB" --resource-type Microsoft.App/jobs -o none 2>/dev/null || true
  az resource delete -g "$RG" -n "$CAPENV" --resource-type Microsoft.App/managedEnvironments -o none 2>/dev/null || true
  az acr delete -n "$ACR" -g "$RG" -o none 2>/dev/null || true
  az keyvault delete -n "$VAULT" -g "$RG" -o none 2>/dev/null || true
  az keyvault purge -n "$VAULT" -l "$LOC" -o none 2>/dev/null || true
  az identity delete -n "$UAI" -g "$RG" -o none 2>/dev/null || true
  az identity delete -n "$KUBELET" -g "$RG" -o none 2>/dev/null || true
  rm -rf "$SCRATCH"
  if [[ "$(az keyvault list-deleted --query "[?name=='$VAULT'] | length(@)" -o tsv 2>/dev/null)" == "1" ]]; then
    echo "destroyed: $VAULT deleted but SOFT-DELETED (purge refused - apply will RECOVER it)"
  else
    echo "destroyed: $VAULT deleted and PURGED (name lock cleared - apply creates fresh)"
  fi
  DESTROY_FAIL=0
  # ARM deletes are ASYNC (live finding 2026-11-06): poll to gone, bounded at
  # 4 min (ACR latency observed 2-4 min), and let the exit code carry it.
  for R in "Microsoft.App/containerApps $APP" "Microsoft.App/jobs $JOB" "Microsoft.App/managedEnvironments $CAPENV" "Microsoft.ContainerRegistry/registries $ACR"; do
    set -- $R
    i=0
    while az resource show -g "$RG" -n "$2" --resource-type "$1" -o none 2>/dev/null; do
      i=$((i+1)); (( i >= ACA_POLL_N )) && break; sleep "$ACA_POLL_S"
    done
    az resource show -g "$RG" -n "$2" --resource-type "$1" -o none 2>/dev/null \
      && echo "  not yet gone: $2 (the resource-group delete below removes it)" || echo "  gone: $2"
  done
  i=0
  while [[ "$(az identity list -g "$RG" --query "[?starts_with(name,'credprox-m46-')] | length(@)" -o tsv 2>/dev/null)" != "0" ]]; do
    i=$((i+1)); (( i >= 12 )) && break; sleep "$ACA_POLL_S"
  done
  [[ "$(az identity list -g "$RG" --query "[?starts_with(name,'credprox-m46-')] | length(@)" -o tsv 2>/dev/null)" == "0" ]] \
    && echo "  gone: credprox-m46-* identities" || echo "  not yet gone: a credprox-m46-* identity (the resource-group delete below removes it)"
  # Role-assignment read-back (row bar: zero). Both identities WE created must
  # carry NO assignments anywhere; the officer assignment was vault-scoped and
  # the vault is purged (its scope cannot hold assignments after purge).
  # A re-run after a partial cleanup can find an identity already deleted: its
  # principal query resolved empty, nothing can be checked for it, and the loop
  # prints SKIPPED per unresolved principal - a vacuous pass must never read
  # as a checked zero.
  for P in "$UAI_PRIN" "$KUBELET_PRIN"; do
    if [[ -z "$P" ]]; then
      echo "  SKIPPED: pre-group role-assignment read-back - a run identity resolved no principal (deleted before this destroy ran)"
      continue
    fi
    i=0
    while [[ "$(az role assignment list --all --query "[?principalId=='$P'] | length(@)" -o tsv 2>/dev/null)" != "0" ]]; do
      i=$((i+1)); (( i >= 12 )) && break; sleep "$ACA_POLL_S"
    done
    [[ "$(az role assignment list --all --query "[?principalId=='$P'] | length(@)" -o tsv 2>/dev/null)" == "0" ]] \
      && echo "  gone: role assignments for a run identity" || echo "  not yet gone: a role assignment for a run identity (re-checked after the group is gone)"
  done
  # The row's RG-gone bar (M46 divergence from M29 keep-RG, disclosed header).
  az group delete -n "$RG" --yes --no-wait 2>/dev/null || true
  i=0
  while [[ "$(az group exists -n "$RG" -o tsv 2>/dev/null)" == "true" ]]; do
    i=$((i+1)); (( i >= ACA_POLL_RG_N )) && break; sleep "$ACA_POLL_S"
  done
  [[ "$(az group exists -n "$RG" -o tsv 2>/dev/null)" == "false" ]] \
    && echo "  gone: resource group $RG" || { echo "  STILL PRESENT: resource group $RG"; DESTROY_FAIL=1; }
  # The verdict: the group is gone (everything in it with it), and no role assignment
  # for a run identity survives anywhere. Assignments can lag the group delete, so poll.
  # Per principal as above: with no principal to query, the check did not run
  # for that identity, and exit 0 here means "group gone", never "zero
  # assignments confirmed".
  for P in "$UAI_PRIN" "$KUBELET_PRIN"; do
    if [[ -z "$P" ]]; then
      echo "  SKIPPED: post-group role-assignment check - a run identity resolved no principal, so its assignments are NOT read back here; a clean exit means the group is gone, not that zero assignments were confirmed"
      continue
    fi
    i=0
    while [[ "$(az role assignment list --all --query "[?principalId=='$P'] | length(@)" -o tsv 2>/dev/null)" != "0" ]]; do
      i=$((i+1)); (( i >= 12 )) && break; sleep "$ACA_POLL_S"
    done
    [[ "$(az role assignment list --all --query "[?principalId=='$P'] | length(@)" -o tsv 2>/dev/null)" == "0" ]] \
      && echo "  gone: role assignments for a run identity (after the group)" \
      || { echo "  STILL PRESENT: a role assignment for a run identity, after the group is gone"; DESTROY_FAIL=1; }
  done
  exit "$DESTROY_FAIL"
  ;;

*)
  echo "usage: $0 apply|material|push|deploy|verify|destroy | --dry-run"; exit 2 ;;
esac
