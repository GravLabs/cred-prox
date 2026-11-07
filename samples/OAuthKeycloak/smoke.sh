#!/usr/bin/env bash
# E2 smoke: real Keycloak issues tokens; the proxy attaches them; the protected API
# validates them. Checks the token cache/single-flight (one token across a concurrent burst)
# and refresh-on-401 (revoked token -> transparent refresh -> success with a new token).
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d --build
trap 'docker compose down' EXIT

for _ in $(seq 1 60); do
  if curl -sf http://localhost:5091/realms/credprox/.well-known/openid-configuration >/dev/null; then break; fi
  sleep 1
done

# Wait for the whole path (proxy -> token -> api) to answer.
token=""
for _ in $(seq 1 60); do
  token=$(curl -sf http://localhost:5081/secrets || true)
  if [ -n "$token" ]; then break; fi
  sleep 1
done
if [ -z "$token" ]; then echo "SMOKE FAILED: the protected path never answered."; exit 1; fi

# Refresh-on-401: revoke the token the API last accepted; the next request must still
# succeed (CredProx refreshed after the 401 — a replay of the revoked token would 401).
# Since M20 (§8.2) the caller's echo shows the token redacted, so the *different* token
# is proven against the API's own record (GET /seen), not the caller's body.
seen_before=$(curl -sf http://localhost:5082/seen)
curl -sf -X POST http://localhost:5082/revoke >/dev/null
refreshed_status=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5081/secrets)
seen_after=$(curl -sf http://localhost:5082/seen)
if [ "$refreshed_status" != "200" ]; then
  echo "SMOKE FAILED: the call after revocation returned HTTP $refreshed_status — no transparent refresh."; exit 1
fi
if [ -z "$seen_after" ] || [ "$seen_after" = "$seen_before" ]; then
  echo "SMOKE FAILED: the API saw no new token after revocation."; exit 1
fi

# Cache/single-flight: a concurrent burst on the warm cache all carries one token —
# proven by the API's count of distinct accepted tokens not moving across the burst.
distinct_before=$(curl -sf http://localhost:5082/seen-count)
for i in $(seq 1 10); do curl -sf http://localhost:5081/secrets -o /dev/null & done
wait
distinct_after=$(curl -sf http://localhost:5082/seen-count)
if [ "$distinct_after" != "$distinct_before" ]; then
  echo "SMOKE FAILED: the burst made the API see $((distinct_after - distinct_before)) new token(s)."; exit 1
fi

echo "SMOKE OK: Keycloak-issued token accepted upstream, refreshed after revocation, cached across a burst."
