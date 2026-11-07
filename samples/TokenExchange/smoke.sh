#!/usr/bin/env bash
# E14 smoke (plan §3.6/§6): two Keycloak users each get their OWN downstream token
# through the CredProx token exchange; an attacker-forged inbound token is rejected
# 401 before any exchange; the caller key is still required; and the downstream never
# accepts the inbound token (its audience check proves the swap).
set -euo pipefail
cd "$(dirname "$0")"

KEY_A="e14a7c3f9b2d48015ae6c8b4d7f29e53"

docker compose up -d --build
trap 'docker compose down' EXIT

for _ in $(seq 1 90); do
  if curl -sf http://localhost:5094/realms/credprox/.well-known/openid-configuration >/dev/null; then break; fi
  sleep 1
done

token_for() {
  curl -sf -X POST \
    -d "grant_type=password" -d "client_id=credprox-frontend" \
    -d "username=$1" -d "password=$1" \
    http://localhost:5094/realms/credprox/protocol/openid-connect/token \
    | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4
}

ALICE=$(token_for alice)
BOB=$(token_for bob)
if [ -z "$ALICE" ] || [ -z "$BOB" ]; then
  echo "SMOKE FAILED: could not obtain user tokens from Keycloak."; exit 1
fi

# Wait for the whole path (proxy -> inbound validation -> exchange -> api) for alice.
# The api echoes "<sub>|<azp>": azp=credprox-proxy proves the downstream received the
# EXCHANGED token, never the inbound one (whose azp is credprox-frontend).
who_a=""
for _ in $(seq 1 60); do
  who_a=$(curl -sf -H "X-CredProx-Key: $KEY_A" -H "Authorization: Bearer $ALICE" http://localhost:5092/ || true)
  if [ -n "$who_a" ]; then break; fi
  sleep 1
done
if [ "$who_a" != "alice|credprox-proxy" ]; then
  echo "SMOKE FAILED: expected alice|credprox-proxy, got '$who_a'."; exit 1
fi

# Second user -> its own downstream token (per-user cache: never cross-served).
who_b=$(curl -sf -H "X-CredProx-Key: $KEY_A" -H "Authorization: Bearer $BOB" http://localhost:5092/ || true)
if [ "$who_b" != "bob|credprox-proxy" ]; then
  echo "SMOKE FAILED: expected bob|credprox-proxy, got '$who_b'."; exit 1
fi

# Forged inbound: an HS256 JWT (attacker's secret, claims alice, right issuer/audience).
# CredProx validates the signature against the realm JWKS BEFORE exchanging anything:
# 401 credprox.inbound_token_invalid, and the 401-vs-502 distinction proves the exchange
# endpoint was never called (an exchange failure would be 502).
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
forged_header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
forged_payload=$(printf '%s' '{"sub":"alice","aud":"credprox-proxy","iss":"http://keycloak:8080/realms/credprox","nbf":0,"iat":0,"exp":9999999999}' | b64url)
forged_sig=$(printf '%s' "$forged_header.$forged_payload" | openssl dgst -sha256 -hmac "attacker-secret" -binary | b64url)
FORGED="$forged_header.$forged_payload.$forged_sig"

forged_body=$(mktemp)
forged_code=$(curl -s -o "$forged_body" -w '%{http_code}' \
  -H "X-CredProx-Key: $KEY_A" -H "Authorization: Bearer $FORGED" http://localhost:5092/)
if [ "$forged_code" != "401" ] || ! grep -q "credprox.inbound_token_invalid" "$forged_body"; then
  echo "SMOKE FAILED: forged inbound expected 401 inbound_token_invalid, got $forged_code: $(cat "$forged_body")"; exit 1
fi
rm -f "$forged_body"

# The caller key is still required: a valid user token without it is 401.
no_key=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ALICE" http://localhost:5092/)
if [ "$no_key" != "401" ]; then
  echo "SMOKE FAILED: keyless request expected 401, got $no_key."; exit 1
fi

# The inbound token sent straight to the downstream is refused: its audience is
# credprox-proxy, not credprox-downstream.
direct=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ALICE" http://localhost:5088/)
if [ "$direct" != "401" ]; then
  echo "SMOKE FAILED: inbound token at downstream expected 401, got $direct."; exit 1
fi

echo "SMOKE OK: alice and bob each get their own exchanged downstream token, forged inbound 401 (no exchange), keyless 401, inbound token refused by the downstream audience check."
