# E3 — MutualTls: a client certificate per cluster

## What it demonstrates

`CredProx.Connection` on a YARP cluster attaches a **client certificate** to every TLS
connection that cluster makes — the certificate is a connection property, not a request
header, so it never touches the caller or the route logic. Two variants:

- **local nginx** (offline, runs in CI): nginx is configured with `ssl_verify_client on`
  and echoes the subject of the certificate it received — the upstream itself proves which
  certificate CredProx presented.
- **public `client.badssl.com`**: a real internet endpoint that refuses connections without
  a client certificate, using BadSSL's published test certificate. No Docker, no accounts.

Plus a **certificate-rotation walkthrough** that swaps the live certificate with no restart.

## What you need

- Local variant: Docker and `openssl`.
- BadSSL variant: nothing (internet for the one download).

## Run it — local variant

```bash
cd samples/MutualTls
./generate-certs.sh                      # sample CA, nginx cert, client cert CN=client-alpha
docker compose up -d                     # nginx requiring a client cert, on :8443
SSL_CERT_FILE=$PWD/certs/ca.crt dotnet run
```

`SSL_CERT_FILE` makes .NET trust the sample CA for the upstream connection — one env var,
no code. (In production you use a real CA and need nothing.)

Now the request **without** a credential — plain HTTP to the proxy:

```bash
curl -s http://localhost:5083/
```

```
CN=client-alpha
```

nginx verified the client certificate CredProx presented and echoed its subject. Callers
over plain HTTP never see or hold the certificate.

## Run it — BadSSL variant

BadSSL publishes its test client certificate for exactly this purpose. Download it into the
key-per-file secret directory (not committed — `secrets.d/` is gitignored):

```bash
mkdir -p secrets.d
curl -s https://badssl.com/certs/client.badssl.com.crt -o /tmp/badssl.crt
curl -s https://badssl.com/certs/client.badssl.com.key -o /tmp/badssl.key
cat /tmp/badssl.crt /tmp/badssl.key > secrets.d/CredProx__Secrets__client-cert
dotnet run -- --variant badssl
```

```bash
curl -s http://localhost:5083/ | head -3
```

`client.badssl.com` confirms the certificate in its page. The only difference between the
variants is one config file (`appsettings.Badssl.json` changes the cluster address); the
connection, the secret reference and the route are identical.

## The exact config

```jsonc
"CredProx": {
  "Connections": {
    "mtls": {
      "ClientCertificate": "secret:client-cert"   // PEM bundle (cert + key) behind a secret ref
      // "ClientCertificatePassword": "secret:…"  // for an encrypted PKCS#8 key
    }
  }
},
"ReverseProxy": {
  "Routes": {
    "upstream": { "ClusterId": "upstream", "Match": { "Path": "/{**catch-all}" } }
  },
  "Clusters": {
    "upstream": {
      "Destinations": { "upstream": { "Address": "https://localhost:8443/" } },
      "Metadata": { "CredProx.Connection": "mtls" }   // this cluster presents the certificate
    }
  }
}
```

The certificate itself is the file `secrets.d/CredProx__Secrets__client-cert`, loaded by
`AddKeyPerFile` — a directory of files is a normal `IConfiguration` provider, so
`secret:client-cert` resolves from it like any other source.

## Certificate rotation, live

With the proxy and nginx still running:

```bash
./generate-certs.sh client-beta     # rewrites secrets.d/CredProx__Secrets__client-cert
curl -s http://localhost:5083/      # → CN=client-beta
```

No restart. The key-per-file provider watches the directory and reloads configuration; the
connection registry sees the new secret value, rebuilds the certificate, and the next
connection to that cluster presents the new client certificate. nginx (still trusting the
same CA) echoes the new subject.

## Verify it

```bash
cd samples/MutualTls && ./smoke.sh   # Docker; what CI runs
```

## What just happened

Tracing `curl http://localhost:5083/`:

1. YARP matches the `upstream` route; the request has no credential and the route names none.
2. The cluster carries `CredProx.Connection=mtls`. When CredProx builds the HTTP client for
   that cluster, it resolves `secret:client-cert`, loads the PEM bundle, and puts the
   certificate into the handler's client credentials.
3. The TLS handshake to nginx presents that certificate; nginx verifies it against the
   sample CA and accepts the connection.
4. nginx returns `$ssl_client_s_dn` — `CN=client-alpha` — so the response body is the
   upstream's own record of which certificate CredProx used.
