#!/usr/bin/env bash
# E11 smoke (plan §6): WireMock as the three-personality vendor + the ops-configured
# host, then the shortened load script asserts throttling, the vendor-429 pause, the
# circuit breaker and health. Needs Docker.
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d
trap 'docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8091/__admin/mappings >/dev/null; then break; fi
  sleep 1
done
curl -sf http://localhost:8091/__admin/mappings >/dev/null \
  || { echo "SMOKE FAILED: WireMock did not come up (docker compose logs wiremock)."; exit 1; }

dotnet run -- &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true; docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:5091/health >/dev/null; then break; fi
  sleep 1
done
curl -sf http://localhost:5091/health >/dev/null \
  || { echo "SMOKE FAILED: the CredProx host did not come up."; exit 1; }

./load.sh
status=$?
kill "$proxy_pid" 2>/dev/null || true
exit "$status"
