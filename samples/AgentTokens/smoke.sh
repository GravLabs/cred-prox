#!/usr/bin/env bash
# E19 smoke: agent tokens as pure config. Proves (Program.cs --smoke):
#   the stub issuer serves the smoke run's GENERATED signing key (kid check);
#   fresh docs-read token as string and as array -> 200; multi-role arrays admit only
#   what they name (200/403); a role naming no rule -> 403; no roles -> 403;
#   unlisted client id -> 401; token older than MaxTokenAge -> 401;
#   the issuer/upstream stub journal proves the caller's bearer token never reaches
#   the upstream. Prints SMOKE OK on success.
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d
trap 'docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8085/__admin/mappings >/dev/null && curl -sf http://localhost:8086/__admin/mappings >/dev/null; then break; fi
  sleep 1
done

dotnet run -- --smoke
