#!/usr/bin/env bash
# E12 smoke (plan §6: "runs without accounts"). Starts the vendor stub, runs the proxy's
# --smoke checks, and tears everything down.
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d
trap 'docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8082/__admin/mappings >/dev/null; then break; fi
  sleep 1
done

dotnet run -- --smoke
