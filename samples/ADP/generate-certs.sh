#!/usr/bin/env bash
# Generates the local test PKI for the ADP example:
#   certs/ca.crt|ca.key              the sample CA (created once, reused)
#   certs/server.crt|server.key      nginx's certificate for localhost (created once)
#   certs/client-alpha.* client-beta.*  client certificates (alpha live, beta = rotation)
#   certs/client-<cn>.pfx            passwordless PKCS#12 per client
#   secrets.d/CredProx__Secrets__adpClientCert
#   secrets.d/CredProx__Secrets__adpClientCert-beta
#                                    base64 PFX bundles — the original adp-auth-cert format,
#                                    so an existing vault secret drops in unchanged.
#
# Usage:
#   ./generate-certs.sh                   # alpha + beta bundles
#   ./generate-certs.sh client-beta       # (re)generate one client only
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p certs secrets.d

if [ ! -f certs/ca.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout certs/ca.key -out certs/ca.crt \
    -subj "/CN=CredProx sample CA"
fi

if [ ! -f certs/server.crt ]; then
  openssl req -newkey rsa:2048 -nodes \
    -keyout certs/server.key -out certs/server.csr -subj "/CN=localhost"
  openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -days 30 -out certs/server.crt \
    -extfile <(printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
  rm -f certs/server.csr
fi

make_client() {
  local cn="$1" bundle="$2"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "certs/${cn}.key" -out "certs/${cn}.csr" -subj "/CN=${cn}"
  openssl x509 -req -in "certs/${cn}.csr" -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -days 30 -out "certs/${cn}.crt" \
    -extfile <(printf 'extendedKeyUsage=clientAuth\n')
  rm -f "certs/${cn}.csr"
  openssl pkcs12 -export -nodes -in "certs/${cn}.crt" -inkey "certs/${cn}.key" \
    -out "certs/${cn}.pfx" -passout pass:
  base64 -w0 "certs/${cn}.pfx" > "secrets.d/${bundle}"
  echo "Wrote secrets.d/${bundle} (base64 passwordless PFX, CN=${cn})."
}

if [ $# -ge 1 ]; then
  case "$1" in
    client-alpha) make_client client-alpha CredProx__Secrets__adpClientCert ;;
    client-beta)  make_client client-beta  CredProx__Secrets__adpClientCert-beta ;;
    *) echo "unknown client: $1" >&2; exit 1 ;;
  esac
else
  make_client client-alpha CredProx__Secrets__adpClientCert
  make_client client-beta  CredProx__Secrets__adpClientCert-beta
fi

echo "Trust the CA when running the proxy:  SSL_CERT_FILE=\$PWD/certs/ca.crt dotnet run"
