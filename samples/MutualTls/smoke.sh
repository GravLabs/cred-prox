#!/usr/bin/env bash
# E3 local-variant smoke: nginx (Docker) requires a client cert and echoes its subject;
# the proxy runs on the host and trusts the sample CA via SSL_CERT_FILE.
set -euo pipefail
cd "$(dirname "$0")"

./generate-certs.sh client-alpha
docker compose up -d
trap 'docker compose down' EXIT

# nginx answers 400 to a TLS connection without a client certificate — that is "up".
for _ in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/ || true)
  if [ "$code" = "400" ]; then break; fi
  sleep 1
done

SSL_CERT_FILE="$PWD/certs/ca.crt" dotnet run -- --smoke
