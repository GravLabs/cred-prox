#!/usr/bin/env bash
# E18 smoke: caller API-key enforcement as pure config. Proves (Program.cs --smoke):
#   missing key -> 401; wrong key -> the same 401 with nothing echoed;
#   accepted key -> proxied 200; the stub journal proves the key header never
#   reaches the upstream. Prints SMOKE OK on success.
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d
trap 'docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8081/__admin/mappings >/dev/null; then break; fi
  sleep 1
done

dotnet run -- --smoke
