#!/usr/bin/env bash
# E6 smoke (plan §6, M36). Offline proof of the ADP shape with the original certificate
# arrangement: nginx enforces a client certificate (signed by the sample CA) on BOTH the
# token path and the API path; the certificate is a base64 passwordless PFX through
# CredProx:Secrets. Proven here:
#   (a) the certificate is presented on the token call AND an API call — nginx's own
#       access log names the subject per path;
#   (b) the bearer is attached (stub journal, vendor side) and scrubbed (caller body);
#   (c) a run WITHOUT the certificate fails cleanly, with no key material in the output;
#   (d) the offline Key Vault witness: the stock provider (loopback stub) rotates the
#       certificate into new connections without a restart;
#   (e) the F1/F2 production-switch guards (variant-guard.sh): exported env reaches
#       --variant real, --variant kv engages the provider, and it fails fast without a URI.
# Prints SMOKE OK on success.
set -euo pipefail
cd "$(dirname "$0")"

./generate-certs.sh

docker compose up -d
# Cleanup runs even when a step fails or the run is interrupted: the certificateless
# section parks secrets.d under bin/ (git-ignored — PFX material must never sit on an
# untracked path where git add -A could pick it up), so the trap restores it too.
trap '{ [ -d bin/secrets.d-stash ] && mv bin/secrets.d-stash secrets.d; } 2>/dev/null; docker compose down' EXIT INT TERM

for _ in $(seq 1 30); do
  if curl -sf http://localhost:8081/__admin/mappings >/dev/null; then break; fi
  sleep 1
done
for _ in $(seq 1 30); do
  if curl -sf http://localhost:8082/__admin/mappings >/dev/null; then break; fi
  sleep 1
done

# nginx must be ACCEPTING TLS before the first probe — container "Started" does not
# mean the listener is up; a cold stack gave one 'Connection refused localhost:8443'
# flake mid-run (2026-11-11), so wait bounded instead of trusting the compose return.
for _ in $(seq 1 30); do
  ready=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/api/v1/employees || true)
  [ "$ready" != "000" ] && break
  sleep 1
done

# nginx itself refuses a certificateless request (TLS layer, before any stub logic).
code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/api/v1/employees || true)
if [ "$code" != "400" ]; then
  echo "SMOKE FAILED: certificateless request to nginx got HTTP $code, want 400"
  exit 1
fi

# Main smoke: cert + bearer + scrub + wire check (Program.cs --smoke).
export SSL_CERT_FILE="$PWD/certs/ca.crt"
if ! dotnet run -- --smoke > .smoke.log 2>&1 || ! grep -q "SMOKE OK" .smoke.log; then
  cat .smoke.log
  echo "SMOKE FAILED: main smoke did not report OK"
  exit 1
fi

# (a) The upstream log names the verified subject on BOTH paths.
nginx_log=$(docker compose logs nginx 2>/dev/null || true)
echo "$nginx_log" | grep -F 'CN=client-alpha | POST /auth/oauth/v2/token?grant_type=client_credentials' >/dev/null || {
  echo "SMOKE FAILED: nginx log shows no client certificate on the token path"
  echo "$nginx_log" | tail -20
  exit 1
}
echo "$nginx_log" | grep -F 'CN=client-alpha | GET /api/v1/employees' >/dev/null || {
  echo "SMOKE FAILED: nginx log shows no client certificate on the API path"
  echo "$nginx_log" | tail -20
  exit 1
}

# (b) Wire evidence: the run recorded to bin/wire-check.txt (untracked); the committed
# wire-check.txt is the curated artifact from a green run. They must match byte for byte.
diff -q bin/wire-check.txt wire-check.txt >/dev/null || {
  echo "SMOKE FAILED: this run's bin/wire-check.txt differs from the committed wire-check.txt"
  diff bin/wire-check.txt wire-check.txt || true
  exit 1
}

# (c) Without the certificate the app fails at startup (eager load) — cleanly: the
# failure names the secret reference, and no key material appears anywhere in the output.
set +e
mkdir -p bin
mv secrets.d bin/secrets.d-stash
dotnet run -- --smoke > .nocert.log 2>&1
rc=$?
mv bin/secrets.d-stash secrets.d
set -e
if [ "$rc" -eq 0 ]; then
  echo "SMOKE FAILED: run without the client certificate unexpectedly succeeded"
  exit 1
fi
SECRET_HEAD=$(head -c 40 secrets.d/CredProx__Secrets__adpClientCert)
if grep -qF -e 'BEGIN' -e "$SECRET_HEAD" -e 'MII' .nocert.log; then
  echo "SMOKE FAILED: certificateless failure output contained key material"
  exit 1
fi

# (d) Offline Key Vault rotation witness: initial value from the stub, beta PFX swapped
# in mid-run; the run ends when the new subject reaches a new connection.
./rotate-kv-stub.sh secrets.d/CredProx__Secrets__adpClientCert
( sleep 6; ./rotate-kv-stub.sh secrets.d/CredProx__Secrets__adpClientCert-beta ) &
rotate_pid=$!
if ! dotnet run -- --kv-smoke > .kvsmoke.log 2>&1; then
  cat .kvsmoke.log
  echo "SMOKE FAILED: Key Vault rotation witness did not report OK"
  exit 1
fi
wait "$rotate_pid"
grep -q "SMOKE OK" .kvsmoke.log || { cat .kvsmoke.log; echo "SMOKE FAILED: kv smoke missing OK"; exit 1; }

# (e) F1/F2 guards for the two documented production switches (offline, no secrets printed).
./variant-guard.sh

# (f) GET-only routing (as the original had): measured once against the live app, then
# pinned here — POST is refused by route matching with 404, GET is proxied with 200.
# This asserts the shipped config's effect; YARP owns method routing, the sample does
# not re-implement it.
dotnet run --no-build > .methodcheck.log 2>&1 &
method_pid=$!
listening=0
for _ in $(seq 1 60); do
  grep -q "Now listening on" .methodcheck.log 2>/dev/null && { listening=1; break; }
  kill -0 "$method_pid" 2>/dev/null || break
  sleep 0.5
done
[ "$listening" = 1 ] || { cat .methodcheck.log; echo "SMOKE FAILED: method probe app did not start listening"; exit 1; }
post_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:5086/adp/api/v1/employees || true)
get_code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5086/adp/api/v1/employees || true)
mlp=$(ss -Hltnp 'sport = :5086' 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
[ -n "$mlp" ] && kill "$mlp" 2>/dev/null || true
kill "$method_pid" 2>/dev/null || true
wait "$method_pid" 2>/dev/null || true
# POST must be REFUSED — 404 (today's measured YARP behavior: no matching route) or 405
# (spec-typical, if YARP ever gets stricter-than-needed handling); 2xx/3xx means the
# method gate leaked. The refusal form is YARP's choice, not this sample's.
if { [ "$post_code" != "404" ] && [ "$post_code" != "405" ]; } || [ "$get_code" != "200" ]; then
  echo "SMOKE FAILED: method probe got POST=$post_code GET=$get_code, want POST refused (404/405; measured 404 on 2026-11-11) GET=200"
  exit 1
fi

echo "SMOKE OK: E6 ADP — mTLS on token and API hops, bearer attached+scrubbed, wire evidence matches, certless run clean, KV rotation witnessed, variant switches guarded, GET-only route enforced (POST 404 / GET 200)."
