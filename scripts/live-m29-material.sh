#!/usr/bin/env bash
# M29 R2.2 vault material for the round-2 live test: create | destroy.
# Writes ONLY into credprox-m29-kv (vault data plane - maintainer-approved gated step).
# Secret hygiene (M26 Phase-4 discipline): values are generated in a scratch
# dir that a trap removes, uploaded via `--file` (never argv, never printed);
# evidence lines carry secret NAMES only.
#
# NAMING RULE (live finding 2026-11-06): `CredProx--<path>` maps to config key
# `CredProx:<path>`, and the shipped CredProx config validator rejects ANY
# foreign key under CredProx at proxy startup - while the vault provider feeds
# every vault secret into every host. So only BINDABLE product paths use the
# CredProx-- namespace; public wiring material lives under CredProxTest--
# (validator-inert). The first live delivery of the old flat names crashed the
# proxy in CrashLoopBackOff on 'unknown configuration key'.
# The material set mirrors the plan (docs/azure-live-test-plan.md R2.2):
#   CredProx--Secrets--jwt-signing-key        RSA-2048 PEM private key (JWT)
#   CredProxTest--jwt-public                  matching public key (verifier pin)
#   CredProx--Secrets--hmac-key               32-byte base64 shared secret
#   CredProx--Secrets--mtls-client-cert       password-encrypted PKCS#12 (base64)
#   CredProx--Secrets--mtls-client-cert-password   its password
#   CredProxTest--mtls-ca                     test CA cert (public, pinned)
#   CredProxTest--mtls-ca-b64                 same CA, base64 single line - the
#                                             PUBLIC trust anchor the proxy
#                                             container installs (plain env via
#                                             the deploy script; entrypoint ->
#                                             update-ca-certificates)
#   CredProx--Secrets--caller-key             inbound edge key
#   CredProxTest--caller-key-hash             sha256:<hex> of the key - the
#                                             caller registry stores ONLY the
#                                             hash (plain env via deploy); the
#                                             battery fetches the VALUE
#   CredProx--Secrets--cp-server-cert         counterparty server cert, CA-issued,
#                                             SAN DNS:localhost,IP:127.0.0.1,
#                                             password-encrypted PKCS#12 (base64)
#   CredProx--Secrets--cp-server-cert-password   its password
# Byte hygiene: every SINGLE-LINE secret is stored WITHOUT a trailing newline
# (openssl outputs piped through `tr -d '\n'`) - the stored bytes must equal
# what the PFX loader, the caller-key header, and the caller-key HASH each see,
# byte-wise. PEM secrets keep their real newlines (the loader needs them).
# Test-only PKI: self-signed CA, trust by pinning (same bar as the E2E mTLS
# tests). destroy deletes the secret versions; the vault PURGE in
# live-infra-destroy-r2.sh is what makes the removal irreversible.
set -euo pipefail
RG=credprox-live-test
VAULT=credprox-m29-kv
NAMES=(CredProx--Secrets--jwt-signing-key CredProxTest--jwt-public
       CredProx--Secrets--hmac-key CredProx--Secrets--mtls-client-cert
       CredProx--Secrets--mtls-client-cert-password CredProxTest--mtls-ca
       CredProxTest--mtls-ca-b64 CredProx--Secrets--caller-key
       CredProxTest--caller-key-hash CredProx--Secrets--cp-server-cert
       CredProx--Secrets--cp-server-cert-password)
LEGACY_FLAT_NAMES=(CredProx--jwt-public CredProx--mtls-ca
       CredProx--mtls-ca-b64 CredProx--caller-key-hash)

[[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
  || { echo "az sign-in required (run manually)"; exit 1; }
az keyvault show -n "$VAULT" -g "$RG" -o none 2>/dev/null \
  || { echo "vault $VAULT absent - run scripts/live-infra-apply-r2.sh first"; exit 1; }

case "${1:-}" in
create)
  D=$(mktemp -d /tmp/credprox-m29-material.XXXXXX)
  trap 'rm -rf "$D"' EXIT
  # JWT signing key pair (PEM with REAL newlines - the loader needs them)
  openssl genrsa -out "$D/jwt.key.pem" 2048 2>/dev/null
  openssl rsa -in "$D/jwt.key.pem" -pubout -out "$D/jwt.pub.pem" 2>/dev/null
  # HMAC shared secret (single line, no trailing newline - byte hygiene rule)
  openssl rand -base64 32 | tr -d '\n' > "$D/hmac.key"
  # inbound caller key (single line, no trailing newline: the header value the
  # battery presents and the hash below must agree byte-wise with the stored
  # secret)
  openssl rand -hex 24 | tr -d '\n' > "$D/caller.key"
  # self-signed CA
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$D/ca.key" -out "$D/ca.crt" -subj "/CN=credprox-m29-test-ca" 2>/dev/null
  # client cert signed by the CA, clientAuth EKU, packed as password-encrypted
  # PKCS#12 (deliberately the encrypted form: the mTLS Connection path has a
  # password channel the JwtAssertion path does not - we exercise it)
  openssl req -newkey rsa:2048 -nodes -keyout "$D/client.key" -out "$D/client.csr" \
    -subj "/CN=credprox-m29-client" 2>/dev/null
  printf 'extendedKeyUsage = clientAuth\n' > "$D/client.ext"
  openssl x509 -req -in "$D/client.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" \
    -CAcreateserial -days 30 -extfile "$D/client.ext" -out "$D/client.crt" 2>/dev/null
  openssl rand -hex 16 | tr -d '\n' > "$D/pfx.pass"
  openssl pkcs12 -export -inkey "$D/client.key" -in "$D/client.crt" \
    -name credprox-m29-client -passout "file:$D/pfx.pass" -out "$D/client.pfx" 2>/dev/null
  base64 -w0 "$D/client.pfx" > "$D/client.pfx.b64"
  # counterparty SERVER cert: CA-issued, serverAuth, SAN localhost+127.0.0.1 -
  # so the proxy's DEFAULT chain validation passes once the PUBLIC CA is in the
  # container trust store (entrypoint), and the battery's strict TLS client too.
  # Password-encrypted PFX again: the password channel proven on the client side
  # is the same channel here.
  openssl req -newkey rsa:2048 -nodes -keyout "$D/server.key" -out "$D/server.csr" \
    -subj "/CN=credprox-m29-counterparty" 2>/dev/null
  printf 'extendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n' > "$D/server.ext"
  openssl x509 -req -in "$D/server.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" \
    -CAcreateserial -days 30 -extfile "$D/server.ext" -out "$D/server.crt" 2>/dev/null
  openssl rand -hex 16 | tr -d '\n' > "$D/spfx.pass"
  openssl pkcs12 -export -inkey "$D/server.key" -in "$D/server.crt" \
    -name credprox-m29-counterparty -passout "file:$D/spfx.pass" -out "$D/server.pfx" 2>/dev/null
  base64 -w0 "$D/server.pfx" > "$D/server.pfx.b64"
  # PUBLIC wiring material the deploy script wires as plain env (see header)
  base64 -w0 "$D/ca.crt" > "$D/ca.b64"
  printf 'sha256:%s' "$(sha256sum "$D/caller.key" | cut -d' ' -f1)" > "$D/caller.key.hash"

  for n in "${NAMES[@]}"; do echo "preparing $n"; done
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--jwt-signing-key' --file "$D/jwt.key.pem" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProxTest--jwt-public' --file "$D/jwt.pub.pem" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--hmac-key' --file "$D/hmac.key" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--mtls-client-cert' --file "$D/client.pfx.b64" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--mtls-client-cert-password' --file "$D/pfx.pass" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProxTest--mtls-ca' --file "$D/ca.crt" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProxTest--mtls-ca-b64' --file "$D/ca.b64" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--caller-key' --file "$D/caller.key" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProxTest--caller-key-hash' --file "$D/caller.key.hash" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--cp-server-cert' --file "$D/server.pfx.b64" -o none
  az keyvault secret set --vault-name "$VAULT" --name 'CredProx--Secrets--cp-server-cert-password' --file "$D/spfx.pass" -o none
  # Self-heal the pre-rename namespace: the old flat names crashed the proxy's
  # config validator on first live delivery (see NAMING RULE header).
  for n in "${LEGACY_FLAT_NAMES[@]}"; do
    az keyvault secret delete --vault-name "$VAULT" --name "$n" -o none 2>/dev/null || true
  done
  echo "material set live (11 secrets); legacy flat names deleted"
  echo "material: $(az keyvault secret list --vault-name "$VAULT" --query 'length(@)' -o tsv) secrets present (expected 11); names only in this log"
  ;;
destroy)
  for n in "${NAMES[@]}"; do
    az keyvault secret delete --vault-name "$VAULT" --name "$n" -o none 2>/dev/null || true
    echo "deleted (versions): $n"
  done
  # Pre-rename flat names (CredProx-- namespace, validator-hostile): a vault
  # rematerialised under the old scheme may still carry them - delete so no
  # run can reintroduce the proxy crash they caused. Absent is the norm.
  for n in "${LEGACY_FLAT_NAMES[@]}"; do
    az keyvault secret delete --vault-name "$VAULT" --name "$n" -o none 2>/dev/null || true
  done
  echo "material now: $(az keyvault secret list --vault-name "$VAULT" --query 'length(@)' -o tsv) secrets (expected 0); irreversible removal = vault purge in live-infra-destroy-r2.sh"
  ;;
*)
  echo "usage: $0 create|destroy"; exit 2 ;;
esac
