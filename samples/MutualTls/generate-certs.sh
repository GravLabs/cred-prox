#!/usr/bin/env bash
# Generates the local test PKI for the MutualTls example:
#   certs/ca.crt|ca.key            the sample CA (created once, reused)
#   certs/server.crt|server.key    nginx's certificate for localhost (created once)
#   secrets.d/CredProx__Secrets__client-cert
#                                  key-per-file secret: the client cert bundle (cert + key)
#
# Usage:
#   ./generate-certs.sh                 # write a client cert with CN=client-alpha
#   ./generate-certs.sh client-beta     # rotation walkthrough: replace the bundle live
set -euo pipefail
cd "$(dirname "$0")"

CLIENT_CN="${1:-client-alpha}"
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

openssl req -newkey rsa:2048 -nodes \
  -keyout "certs/${CLIENT_CN}.key" -out "certs/${CLIENT_CN}.csr" -subj "/CN=${CLIENT_CN}"
openssl x509 -req -in "certs/${CLIENT_CN}.csr" -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -days 30 -out "certs/${CLIENT_CN}.crt" \
  -extfile <(printf 'extendedKeyUsage=clientAuth\n')
rm -f "certs/${CLIENT_CN}.csr"

cat "certs/${CLIENT_CN}.crt" "certs/${CLIENT_CN}.key" > secrets.d/CredProx__Secrets__client-cert

echo "Wrote secrets.d/CredProx__Secrets__client-cert with CN=${CLIENT_CN}."
echo "Trust the CA when running the proxy:  SSL_CERT_FILE=\$PWD/certs/ca.crt dotnet run"
