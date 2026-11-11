#!/usr/bin/env bash
# F1/F2 regression guards (M36 security pass). The two documented production switches had
# no coverage, and that is how empty placeholder keys shipped over them: a JSON source added
# AFTER the environment wins in .NET configuration. These guards are offline only —
# the 'real' switch is proven as far as "starts listening with exported values" (no vendor
# call is made); the kv switch is aimed at a guaranteed-unresolvable .invalid host.
# No secret or key content is ever printed.
# Usage: variant-guard.sh [a|b|c]   (default: all — every guard must pass)
# Builds Debug itself and always runs that configuration, so it works no matter what
# was built before (an unbuilt or Release-only tree used to give a confusing red).
set -euo pipefail
cd "$(dirname "$0")"
RUN="${1:-all}"
dotnet build -c Debug -v q --nologo >/dev/null \
  || { echo "GUARD FAILED: sample build failed (re-run: dotnet build -c Debug)"; exit 1; }

fail(){ echo "GUARD FAILED: $1"; shift; for f in "$@"; do [ -f "$f" ] && tail -20 "$f"; done; exit 1; }
run_this(){ [ "$RUN" = all ] || [ "$RUN" = "$1" ]; }

# (a) F1: --variant real with ClientId + secrets exported reaches the app and starts
# listening — no empty placeholder in appsettings.RealAdp.json may shadow them.
if run_this a; then
export CredProx__Credentials__adp__ClientId=guard-client
export CredProx__Secrets__adpClientSecret=guard-secret
export CredProx__Secrets__adpClientCert="$(cat secrets.d/CredProx__Secrets__adpClientCert)"
dotnet run --no-build -c Debug -- --variant real > .variant-real.log 2>&1 &
guard_pid=$!
started=0
for _ in $(seq 1 60); do
  if grep -q "Now listening on" .variant-real.log 2>/dev/null; then started=1; break; fi
  if ! kill -0 "$guard_pid" 2>/dev/null; then break; fi
  sleep 0.5
done
# Kill the app by the socket owner (dotnet run can orphan the app process), then the wrapper.
listen_pid=$(ss -Hltnp 'sport = :5086' 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
if [ -n "${listen_pid:-}" ]; then kill "$listen_pid" 2>/dev/null || true; fi
kill "$guard_pid" 2>/dev/null || true
wait "$guard_pid" 2>/dev/null || true
[ "$started" = 1 ] || fail "--variant real with exported values did not start listening (env shadowed?)" .variant-real.log
if grep -q "ClientId is required" .variant-real.log; then
  fail "exported ClientId was shadowed by a committed placeholder" .variant-real.log
fi
fi

# (b) F2: --variant kv with KeyVault__Uri exported must ENGAGE the provider — proven by the
# unresolvable host being named in the failure, never by a silent skip into an unresolved
# secret: reference.
if run_this b; then
rc=0
env -u CredProx__Credentials__adp__ClientId -u CredProx__Secrets__adpClientSecret \
    -u CredProx__Secrets__adpClientCert \
    KeyVault__Uri=https://credprox-guard.invalid/ \
    timeout 150 dotnet run --no-build -c Debug -- --variant kv > .variant-kv.log 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "--variant kv against an unresolvable vault host unexpectedly succeeded" .variant-kv.log
grep -qi "credprox-guard.invalid" .variant-kv.log \
  || fail "--variant kv never dialed the exported KeyVault__Uri (provider skipped?)" .variant-kv.log
if grep -q "does not resolve" .variant-kv.log; then
  fail "--variant kv fell through to an unresolved secret: the provider was never added" .variant-kv.log
fi
fi

# (c) F2 fail-fast: --variant kv with no URI must refuse at startup naming KeyVault:Uri.
if run_this c; then
rc=0
env -u CredProx__Credentials__adp__ClientId -u CredProx__Secrets__adpClientSecret \
    -u CredProx__Secrets__adpClientCert -u KeyVault__Uri \
    timeout 60 dotnet run --no-build -c Debug -- --variant kv > .variant-kvnouri.log 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "--variant kv without KeyVault__Uri unexpectedly succeeded" .variant-kvnouri.log
grep -q "KeyVault:Uri" .variant-kvnouri.log \
  || fail "--variant kv without a URI did not fail fast naming KeyVault:Uri" .variant-kvnouri.log
fi

# None of the guard outputs may carry key material.
sec_head=$(head -c 40 secrets.d/CredProx__Secrets__adpClientCert)
for f in .variant-real.log .variant-kv.log .variant-kvnouri.log; do
  [ -f "$f" ] || continue
  if grep -qF -e 'BEGIN' -e 'MII' -e "$sec_head" "$f"; then
    fail "guard output contains key material" "$f"
  fi
done

echo "VARIANT GUARDS OK: real keeps exported env, kv engages the provider, kv without a URI fails fast."
