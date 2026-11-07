#!/usr/bin/env bash
# The PUBLIC test-CA certificate (a trust ANCHOR, not a secret) arrives as a base64 of
# its PEM via CREDPROX_TEST_CA_PEM_B64, so the proxy's DEFAULT chain validation accepts
# the counterparty's CA-issued server certificate on the in-pod mTLS hop without any
# library change. Secret material (private keys, PFXes, passwords, caller key) never
# travels this way - it arrives only from Key Vault through CredProx's config provider.
# Unset elsewhere (counterparty, battery, smoke) is normal: no-op.
set -euo pipefail
if [[ -n "${CREDPROX_TEST_CA_PEM_B64:-}" ]]; then
  printf '%s' "$CREDPROX_TEST_CA_PEM_B64" | base64 -d > /usr/local/share/ca-certificates/credprox-m29-ca.crt
  update-ca-certificates >/dev/null
  echo "entrypoint: test CA installed into the container trust store (public material)"
fi
exec dotnet /app/AzureContainerApps.dll "$@"
