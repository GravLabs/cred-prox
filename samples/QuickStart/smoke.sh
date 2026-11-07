#!/usr/bin/env bash
# E1 smoke against the WireMock stand-in (plan §6: "smoke test against a WireMock stand-in").
# The no-Docker equivalent is: dotnet run -- --smoke
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d
trap 'docker compose down' EXIT

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8088/__admin/mappings >/dev/null; then break; fi
  sleep 1
done

CredProx__Destinations__echo__Template=http://localhost:8088 \
ReverseProxy__Clusters__echo__Destinations__echo__Address=http://localhost:8088/ \
  dotnet run -- &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true; docker compose down' EXIT

for _ in $(seq 1 30); do
  echo_headers=$(curl -sf http://localhost:5080/echo/headers 2>/dev/null || true)
  # Since M20 (§8.2) the injected key is scrubbed from the echo body the caller sees,
  # so the credential's arrival is proven against WireMock's request journal — the
  # stub's own record — while the caller's echo shows the redaction.
  journal=$(curl -sf http://localhost:8088/__admin/requests 2>/dev/null || true)
  if printf '%s' "$echo_headers" | grep -q 'redacted' \
     && printf '%s' "$journal" | grep -q demo-static-key; then
    echo "SMOKE OK: WireMock's journal shows the X-API-Key header CredProx attached; the caller's echo shows it redacted."
    exit 0
  fi
  sleep 1
done

echo "SMOKE FAILED: the upstream never saw the credential header (or the caller's echo is unredacted)."
exit 1
