#!/usr/bin/env bash
# M29 R2.5 one-command DESTROY of every round-2 object, dependency order:
# app + battery job -> environment -> ACR -> vault (delete AND purge) -> the
# two identities.
# The RESOURCE GROUP SURVIVES (same as round 1): destroy leaves a deterministic
# empty container so apply can re-run without the gate-step-1 create; the plan
# gate list's final cleanup removes the RG explicitly.
#
# Vault purge is deliberate (round-1 Phase-5 decision): a plain delete
# name-locks the vault and breaks the one-command cycle. Irreversible by
# design. Uses `az resource delete` so NO containerapp CLI extension is needed
# for teardown - the exit path must never depend on an extension install.
# Run-manually scope; touches only credprox-m29-* objects.
set -euo pipefail
# Region for the vault purge (arg 1) - MUST match what apply used
# (default matches live-infra-apply-r2.sh; decision 2026-11-06: Americas only).
LOC="${1:-eastus}"
RG=credprox-live-test
VAULT=credprox-m29-kv
APP=credprox-m29-app
JOB=credprox-m29-battery
CAPENV=credprox-m29-env
ACR=credproxm29reg

# Idempotent: tolerate already-gone states (destroy may be re-run).
# App AND job before the environment that hosts them (G3: nothing references
# vault/registry after this line pair - vault purge and ACR delete follow).
az resource delete -g "$RG" -n "$APP" --resource-type Microsoft.App/containerApps -o none 2>/dev/null || true
az resource delete -g "$RG" -n "$JOB" --resource-type Microsoft.App/jobs -o none 2>/dev/null || true
az resource delete -g "$RG" -n "$CAPENV" --resource-type Microsoft.App/managedEnvironments -o none 2>/dev/null || true
az acr delete -n "$ACR" -g "$RG" -o none 2>/dev/null || true
az keyvault delete -n "$VAULT" -g "$RG" -o none 2>/dev/null || true
# purge needs the vault location (arg 1, same region apply deployed - the vault
# is NOT in a special region anymore); refusal is non-fatal but the read-back
# below states the real state.
az keyvault purge -n "$VAULT" -l "$LOC" -o none 2>/dev/null || true
az identity delete -n credprox-m29-uai -g "$RG" -o none 2>/dev/null || true
az identity delete -n credprox-m29-kubelet -g "$RG" -o none 2>/dev/null || true

if [[ "$(az keyvault list-deleted --query "[?name=='$VAULT'] | length(@)" -o tsv 2>/dev/null)" == "1" ]]; then
  echo "destroyed: $VAULT deleted but SOFT-DELETED (purge refused - apply will RECOVER it)"
else
  echo "destroyed: $VAULT deleted and PURGED (name lock cleared - apply creates fresh)"
fi
echo "destroyed: $APP, $JOB, $CAPENV, $ACR, credprox-m29-uai, credprox-m29-kubelet (read-backs:)"
# live finding 2026-11-06: ARM deletes are ASYNC - a single immediate `resource show`
# raced the ARM cache and printed "STILL PRESENT" for a registry that was in fact
# deleted moments later. And the script exited 0 even with a read-back present, so the
# caller's OK marker masked a real leftover. Poll until gone (bounded), then let the
# EXIT CODE reflect the read-backs.
DESTROY_FAIL=0
for R in "Microsoft.App/containerApps $APP" "Microsoft.App/jobs $JOB" "Microsoft.App/managedEnvironments $CAPENV" "Microsoft.ContainerRegistry/registries $ACR"; do
  set -- $R
  i=0
  # live finding 2026-11-06: ACR delete latency observed 2-4 min on ARM - a 2-min
  # poll cap honestly FAILed a deletion that landed ~1 min later. Cap to 4 min.
  while az resource show -g "$RG" -n "$2" --resource-type "$1" -o none 2>/dev/null; do
    i=$((i+1)); (( i >= 24 )) && break; sleep 10
  done
  az resource show -g "$RG" -n "$2" --resource-type "$1" -o none 2>/dev/null \
    && { echo "  STILL PRESENT: $2"; DESTROY_FAIL=1; } || echo "  gone: $2"
done
i=0
while [[ "$(az identity list -g "$RG" --query "[?starts_with(name,'credprox-')] | length(@)" -o tsv 2>/dev/null)" != "0" ]]; do
  i=$((i+1)); (( i >= 12 )) && break; sleep 10
done
[[ "$(az identity list -g "$RG" --query "[?starts_with(name,'credprox-')] | length(@)" -o tsv 2>/dev/null)" == "0" ]] \
  && echo "  gone: credprox-* identities" || { echo "  STILL PRESENT: a credprox-* identity"; DESTROY_FAIL=1; }
exit "$DESTROY_FAIL"
