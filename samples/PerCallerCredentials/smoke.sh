#!/usr/bin/env bash
# E7 smoke: two callers mapped to two Keycloak accounts on one route; a read-only caller
# blocked from POST by its allow-list; audit records for all three calls.
set -euo pipefail
cd "$(dirname "$0")"

KEY_A="9f3a7c2e5b8d1460ae7c4f2b9d8e1a63"
KEY_B="2c5e8b1f7a3d9604c8b2e5f7a1d39c68"
KEY_RO="7b1d4e8a2c6f9035d7e1b8a4c2f60d93"

docker compose up -d --build
trap 'docker compose down' EXIT

for _ in $(seq 1 60); do
  if curl -sf http://localhost:5093/realms/credprox/.well-known/openid-configuration >/dev/null; then break; fi
  sleep 1
done

# Wait for the whole path (proxy -> token -> api) to answer for caller app-a.
who_a=""
for _ in $(seq 1 60); do
  who_a=$(curl -sf -H "X-CredProx-Key: $KEY_A" http://localhost:5083/ || true)
  if [ -n "$who_a" ]; then break; fi
  sleep 1
done
if [ "$who_a" != "credprox-app-a" ]; then
  echo "SMOKE FAILED: expected credprox-app-a, got '$who_a'."; exit 1
fi

# Second caller, same route -> a DIFFERENT Keycloak account.
who_b=$(curl -sf -H "X-CredProx-Key: $KEY_B" http://localhost:5083/ || true)
if [ "$who_b" != "credprox-app-b" ]; then
  echo "SMOKE FAILED: expected credprox-app-b, got '$who_b'."; exit 1
fi

# Read-only caller: GET is allowed, POST is blocked by its allow-list (403, never forwarded).
ro_get=$(curl -sf -o /dev/null -w '%{http_code}' -H "X-CredProx-Key: $KEY_RO" http://localhost:5083/)
if [ "$ro_get" != "200" ]; then
  echo "SMOKE FAILED: read-only GET expected 200, got $ro_get."; exit 1
fi
ro_post=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-CredProx-Key: $KEY_RO" http://localhost:5083/)
if [ "$ro_post" != "403" ]; then
  echo "SMOKE FAILED: read-only POST expected 403, got $ro_post."; exit 1
fi

# No key at all -> 401.
no_key=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5083/)
if [ "$no_key" != "401" ]; then
  echo "SMOKE FAILED: keyless request expected 401, got $no_key."; exit 1
fi

# Audit records for all three callers (the LoggerAuditSink line per call).
logs=$(docker compose logs proxy)
for want in \
  "credprox.audit credprox.proxied_call: caller=app-a" \
  "credprox.audit credprox.proxied_call: caller=app-b" \
  "credprox.audit credprox.rejected_call: caller=app-readonly"
do
  if ! printf '%s\n' "$logs" | grep -qF "$want"; then
    echo "SMOKE FAILED: proxy logs missing audit record: $want"; exit 1
  fi
done

echo "SMOKE OK: two callers -> two vendor accounts, allow-list 403, keyless 401, audit records for all three."
