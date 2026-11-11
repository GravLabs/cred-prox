#!/usr/bin/env bash
# Installs (or replaces) the loopback Key Vault stub's mapping for the certificate
# secret, from a base64 PFX bundle written by generate-certs.sh. Bumping
# attributes.updated is what makes the configuration provider accept the new value —
# the same signal a real vault rotation carries. Usage:
#   ./rotate-kv-stub.sh secrets.d/CredProx__Secrets__adpClientCert        # initial
#   ./rotate-kv-stub.sh secrets.d/CredProx__Secrets__adpClientCert-beta   # rotation
set -euo pipefail
cd "$(dirname "$0")"

BUNDLE="${1:?usage: rotate-kv-stub.sh <bundle-file>}"
VALUE=$(cat "$BUNDLE")
UPDATED=$(date +%s)

# The mapping body contains the PFX: write it only under bin/ (git-ignored) and let the
# EXIT trap remove it even when a curl fails mid-run.
mkdir -p bin
MAPPING=bin/kv-mapping.json
trap 'rm -f "$MAPPING"' EXIT

python3 - "$VALUE" "$UPDATED" > "$MAPPING" <<'PY'
import json, sys
value, updated = sys.argv[1].strip(), int(sys.argv[2])
print(json.dumps({
    "name": "kv-adpClientCert",
    "priority": 5,
    "request": {"method": "GET",
                "urlPathPattern": "/secrets/CredProx--Secrets--adpClientCert/?"},
    "response": {"status": 200,
                 "headers": {"Content-Type": "application/json"},
                 "jsonBody": {"value": value,
                              "id": "https://credprox-adp-sample.vault.azure.net"
                                    "/secrets/CredProx--Secrets--adpClientCert/v-" + str(updated),
                              "attributes": {"enabled": True, "updated": updated}}},
}))
PY

curl -sf -X DELETE "http://localhost:8082/__admin/mappings/name/kv-adpClientCert" >/dev/null 2>&1 || true
curl -sf -X POST --data @"$MAPPING" "http://localhost:8082/__admin/mappings" >/dev/null
rm -f "$MAPPING"
echo "KV stub now serves the bundle from ${BUNDLE} (attributes.updated=${UPDATED})."
