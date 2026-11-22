#!/usr/bin/env bash
# M32 consumer compatibility matrix (docs/consumer-compatibility.md).
#
# Rebuilds the matrix from a clean scratch dir exactly as a real consumer would:
# dotnet new + dotnet package add against the machine-local `credprox` registry source
# (declared in the user-level NuGet config; its URL never appears in this file) plus
# nuget.org. No project references, no repo NuGet.Config, no repo Directory.*.props
# anywhere near the scratch tree. Isolated NUGET_PACKAGES; http-cache cleared.
#
# Usage:  consumer-compat.sh [cell ...]      (no args = all cells)
# Cells:  web webapi auth container net8 net9 drift testing keys keytokens hmac loginexchange oauth operations
# Results append to $M32_SCRATCH/results.tsv:  cell<TAB>PASS|FAIL<TAB>detail
#
# NO pipefail (early-exit grep would SIGPIPE the recorder); PASS/FAIL is recorded per
# cell and the exit code is non-zero if any cell fails.
set -u

FEED=${M32_FEED:-credprox}
# Default version is the repo's own — the cells add packages that must exist in the
# built feed; a stale hard-coded pin makes every dotnet package add fail with NU1102.
VERSION=${M32_VERSION:-$(sed -n 's|.*<Version>\(.*\)</Version>.*|\1|p' "$(dirname "$0")/../build/Version.props" | head -1)}
REPO=${M32_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
# Default scratch lives in the checkout (artifacts/ is gitignored), never on tmpfs:
# a tmpfs quota can fabricate FAILs on disk-hungry cells. It is a dedicated
# subdirectory because each cell wipes and recreates its own dir under SCRATCH.
SCRATCH=${M32_SCRATCH:-$REPO/artifacts/consumer-compat}
RESULTS=$SCRATCH/results.tsv
WIREMOCK_IMAGE=wiremock/wiremock:3.9.2   # same stand-in as samples/QuickStart
export NUGET_PACKAGES=$SCRATCH/pkg
export DOTNET_CLI_TELEMETRY_OPTOUT=1

mkdir -p "$SCRATCH"
# Scratch is its own central-package-management boundary. Without this file a cell dir
# inside the checkout discovers the repo-root Directory.Packages.props: dotnet package
# add then rewrites THAT file (stripping its final newline) and cell restores inherit
# the repo's pins. Cells that want CPM (drift) carry their own closer props file.
cat > "$SCRATCH/Directory.Packages.props" << 'EOF'
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>
</Project>
EOF
# Same boundary for Directory.Build.props: without this closer a default (in-checkout)
# scratch inherits the repo's library policy — TreatWarningsAsErrors + GenerateDocumentationFile
# hit the scaffold with CS1591, and the TargetFrameworks leak makes a net8/net9 cell restore
# against net10.0 so its NU1202 pin never evaluates. This file must stay an empty <Project />:
# it only stops the walk-up.
cat > "$SCRATCH/Directory.Build.props" << 'EOF'
<Project />
EOF
: > "$RESULTS"
dotnet nuget locals http-cache --clear >/dev/null 2>&1 || true

record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; echo "== $1: $2 ($3)"; }

wait_for() { # url, name
  for _ in $(seq 1 30); do
    curl -sf "$1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "TIMEOUT waiting for $2 ($1)" >&2
  return 1
}

start_wiremock() {
  docker rm -f m32-wm >/dev/null 2>&1 || true
  docker run -d --name m32-wm -p 8088:8080 \
    -v "$REPO/samples/QuickStart/wiremock/mappings:/home/wiremock/mappings:ro" \
    "$WIREMOCK_IMAGE" --global-response-templating >/dev/null
  wait_for http://localhost:8088/__admin/mappings WireMock
}

stop_wiremock() { docker rm -f m32-wm >/dev/null 2>&1 || true; }

# --- consumer app templates ----------------------------------------------------

# Pin every scaffolded consumer to the repo's built feed: <clear /> drops the machine's
# inherited package sources — a configured `credprox` feed carrying RELEASED CredProx
# packages wins version ties against the locally built feed and silently tests released
# bytes instead of these packages.
write_local_feed_config() { # dir [extra-xml-inside-configuration]
  local dir=$1 extra=${2:-}
  {
    printf '%s\n' '<?xml version="1.0" encoding="utf-8"?>' '<configuration>'
    cat << EOF
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="credprox-build" value="$REPO/artifacts/packages" />
  </packageSources>
EOF
    # The scaffold declares its own mapping so it stays self-consistent in any folder:
    # a scratch inside the checkout inherits the repo-root NuGet.Config mapping (CPM's
    # NU1507 guard), and its CredProx* -> credprox-local pattern references a source
    # this cleared config does not define, which would NU1100 every dotnet package add
    # (source lookup stops at this file; the mapping does not). Mapping CredProx* to
    # credprox-build is the slice 3 cold-cache rule anyway: the built feed, never the
    # released bytes. A caller passing its own mapping (the drift cell) opts out.
    case "$extra" in
      *packageSourceMapping*) ;;
      *) cat << 'EOF'
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="credprox-build">
      <package pattern="CredProx*" />
    </packageSource>
  </packageSourceMapping>
EOF
        ;;
    esac
    [ -n "$extra" ] && printf '%s\n' "$extra"
    printf '%s\n' '</configuration>'
  } > "$dir/NuGet.config"
}

# The minimal-API host shape from samples/QuickStart (plan 6 E1), rebuilt here from
# packages only: static key credential, secret from configuration, /echo route.
scaffold_web() { # dir [extra-csproj-lines]
  local dir=$1 extra=${2:-}
  rm -rf "$dir" && mkdir -p "$dir"
  write_local_feed_config "$dir"
  cat > "$dir/app.csproj" << 'EOF'
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    ROOTPROPS    BUILDPROPS  </PropertyGroup>
  <ItemGroup>
    PKGREFS  </ItemGroup>
</Project>
EOF
  sed -e "s|ROOTPROPS||" -e "s|BUILDPROPS||" -e "s|PKGREFS||" -i "$dir/app.csproj"
  [ -n "$extra" ] && sed -i "s|</PropertyGroup>|$extra</PropertyGroup>|" "$dir/app.csproj"
  cat > "$dir/Program.cs" << 'EOF'
using CredProx;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();
builder.WebHost.UseUrls("http://127.0.0.1:5080");
var app = builder.Build();
app.MapReverseProxy();
app.Run();
EOF
  cat > "$dir/appsettings.json" << 'EOF'
{
  "CredProx": {
    "Destinations": { "echo": { "Template": "http://localhost:8088" } },
    "Credentials": {
      "echo-key": { "Type": "StaticKey", "Name": "X-API-Key", "Secret": "secret:echo-key" }
    },
    "Secrets": { "echo-key": "demo-static-key" }
  },
  "ReverseProxy": {
    "Routes": {
      "echo": {
        "ClusterId": "echo",
        "Match": { "Path": "/echo/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/echo" } ],
        "Metadata": { "CredProx.Destination": "echo", "CredProx.Credential": "echo-key" }
      }
    },
    "Clusters": {
      "echo": { "Destinations": { "echo": { "Address": "http://localhost:8088/" } } }
    }
  }
}
EOF
}

add_credprox_pkg() { # dir pkg...
  # No --source here: the SDK resolves it as a path/URL, not a configured-source name.
  # The scratch project's own NuGet.config (write_local_feed_config) supplies the
  # `credprox-build` source pointing at artifacts/packages; without a built feed
  # the restore fails and the cell records FAIL honestly.
  local dir=$1; shift
  local p out code
  for p in "$@"; do
    # Keep the add output: a swallowed NU* error makes a FAIL cell undiagnosable.
    # Same shape as the net8/net9 cells' add.log capture.
    out=$(cd "$dir" && dotnet package add "$p" --version "$VERSION" 2>&1)
    code=$?
    printf '%s\n' "$out" > "$dir/add-$p.log"
    if [ $code -ne 0 ]; then return 1; fi
  done
}

# E1 smoke against the WireMock stand-in (same assertions as samples/QuickStart/smoke.sh:
# the raw credential is proven in WireMock's journal, the caller's echo shows the redaction).
run_app() { # dir — exec the built dll directly: `dotnet run` would leave the app as an
  # orphan child on kill and strand port 5080 for every later cell.
  local dir=$1 asm
  asm=$(basename "$(ls "$dir"/*.csproj | head -1)" .csproj)
  (cd "$dir" && ASPNETCORE_URLS=http://127.0.0.1:5080 ASPNETCORE_ENVIRONMENT=Production exec dotnet "bin/Debug/net10.0/$asm.dll" > "$dir/run.log" 2>&1) &
}

smoke_web() { # dir
  local dir=$1
  run_app "$dir"
  local pid=$!
  local i detail
  detail="proxy never answered"
  for i in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then detail="proxy exited early (see run.log)"; break; fi
    local echo_headers journal
    echo_headers=$(curl -sf http://127.0.0.1:5080/echo/headers 2>/dev/null || true)
    journal=$(curl -sf http://localhost:8088/__admin/requests 2>/dev/null || true)
    if printf '%s' "$echo_headers" | grep -q 'redacted' && printf '%s' "$journal" | grep -q 'demo-static-key'; then
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
        echo "SMOKE OK: journal shows the attached X-API-Key; caller echo shows [redacted]"
        return 0
    fi
    [ -n "$echo_headers" ] && detail="echo answered without redaction/journal match"
    sleep 1
  done
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  echo "SMOKE FAILED: $detail" >&2
  return 1
}

build_warnaserror() { # dir -> full restore+build log in $dir/build.log; exit = build's (never tail's)
  local dir=$1
  (cd "$dir" && dotnet restore > "$dir/build.log" 2>&1 && dotnet build --no-restore -warnaserror >> "$dir/build.log" 2>&1)
}

# --- cells ----------------------------------------------------------------------

cell_web() {
  local d=$SCRATCH/web
  scaffold_web "$d"
  add_credprox_pkg "$d" CredProx || { record web FAIL "package add"; return; }
  build_warnaserror "$d" || { record web FAIL "build, see $d/build.log"; return; }
  start_wiremock || { record web FAIL "wiremock start"; return; }
  if smoke_web "$d"; then record web PASS "restore+warnaserror build+WireMock smoke"
  else record web FAIL "smoke (see $d/run.log)"; fi
  stop_wiremock
}

cell_webapi() {
  local d=$SCRATCH/webapi
  rm -rf "$d" && mkdir -p "$d"
  (cd "$d" && dotnet new webapi --no-openapi -o . >/dev/null 2>&1) || { record webapi FAIL "template"; return; }
  write_local_feed_config "$d"
  add_credprox_pkg "$d" CredProx || { record webapi FAIL "package add"; return; }
  # controllers stay; CredProx routes join them
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
s = p.read_text()
s = s.replace("var app = builder.Build();", """builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();
var app = builder.Build();""")
s = s.replace("app.UseHttpsRedirection();", "app.UseHttpsRedirection();\napp.MapReverseProxy();")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record webapi FAIL "program rewrite"; return; }
  # point the template's launch profile off https; run on http only
  python3 - "$d/appsettings.json" << 'PYEOF'
import sys, json, pathlib
p = pathlib.Path(sys.argv[1])
cfg = json.loads(p.read_text())
cfg["CredProx"] = {
  "Destinations": {"echo": {"Template": "http://localhost:8088"}},
  "Credentials": {"echo-key": {"Type": "StaticKey", "Name": "X-API-Key", "Secret": "secret:echo-key"}},
  "Secrets": {"echo-key": "demo-static-key"},
}
cfg["ReverseProxy"] = {
  "Routes": {"echo": {"ClusterId": "echo", "Match": {"Path": "/echo/{**catch-all}"},
    "Transforms": [{"PathRemovePrefix": "/echo"}],
    "Metadata": {"CredProx.Destination": "echo", "CredProx.Credential": "echo-key"}}},
  "Clusters": {"echo": {"Destinations": {"echo": {"Address": "http://localhost:8088/"}}}},
}
p.write_text(json.dumps(cfg, indent=2))
PYEOF
  [ $? -ne 0 ] && { record webapi FAIL "appsettings rewrite"; return; }
  build_warnaserror "$d" || { record webapi FAIL "build, see $d/build.log"; return; }
  start_wiremock || { record webapi FAIL "wiremock start"; return; }
  # --no-launch-profile: the template's launchSettings would override ASPNETCORE_URLS
  run_app "$d"
  local pid=$! ok=0
  wait_for http://127.0.0.1:5080/echo/headers proxy || true
  if curl -sf http://127.0.0.1:5080/weatherforecast >/dev/null 2>&1; then
    if curl -sf http://127.0.0.1:5080/echo/headers | grep -q redacted \
       && curl -sf http://localhost:8088/__admin/requests | grep -q demo-static-key; then ok=1; fi
  fi
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  stop_wiremock
  if [ "$ok" = 1 ]; then record webapi PASS "controllers + CredProx route coexist, smoke green"
  else record webapi FAIL "see $d/run.log"; fi
}

cell_netframework() { # cellid tfm
  local cell=$1 tfm=$2 d
  d=$SCRATCH/$cell
  rm -rf "$d" && mkdir -p "$d"
  (cd "$d" && dotnet new classlib -o . >/dev/null 2>&1) || { record "$cell" FAIL "template"; return; }
  sed -i "s|net10.0|$tfm|" "$d"/*.csproj
  local out
  out=$(cd "$d" && dotnet package add CredProx --version "$VERSION" 2>&1)
  local code=$?
  printf '%s\n' "$out" > "$d/add.log"
  if [ $code -ne 0 ]; then
    if printf '%s' "$out" | grep -q NU1202; then
      local msg
      msg=$(printf '%s' "$out" | grep -oE "CredProx [0-9.]+ is not compatible with [^ ]*" | head -1)
      record "$cell" PASS "NU1202 as expected: ${msg:-see $d/add.log}"
    else
      record "$cell" FAIL "refused, but not with NU1202: $(printf '%s' "$out" | grep -oE 'NU[0-9]+' | sort -u | tr '\n' ' ')"
    fi
  else
    record "$cell" FAIL "restore unexpectedly SUCCEEDED on $tfm"
  fi
}

cell_drift() {
  local d=$SCRATCH/drift
  scaffold_web "$d"
  # central package management + strict build, like a careful consumer.
  # Findings kept out of the pin list deliberately:
  # - NU1510: explicit Microsoft.Extensions.* refs are flagged as unnecessary on net10 web SDK
  #   (transitive package pruning), so they are not referenced here.
  # - CPM + a private feed plus nuget.org triggers NU1507 unless sources are mapped by key.
  cat > "$d/Directory.Packages.props" << 'EOF'
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="CredProx" Version="VERSION" />
    <PackageVersion Include="CredProx.Azure" Version="VERSION" />
    <PackageVersion Include="Yarp.ReverseProxy" Version="2.3.0" />
    <PackageVersion Include="Azure.Identity" Version="1.17.0" />
  </ItemGroup>
</Project>
EOF
  sed -i "s/VERSION/$VERSION/g" "$d/Directory.Packages.props"
  # CPM over two sources triggers NU1507 unless every source is mapped by KEY. The
  # mapping goes through the same helper so the cleared candidate feed stays declared,
  # and CredProx* maps to credprox-build — the built feed. Mapping it to the machine's
  # `credprox` key instead puts RELEASED bytes in scope and a cold-cache run cannot
  # tell the two apart (the slice 3 cold-cache lesson).
  write_local_feed_config "$d" '  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="credprox-build">
      <package pattern="CredProx*" />
    </packageSource>
  </packageSourceMapping>'
  python3 - "$d/app.csproj" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = s.replace("<Nullable>enable</Nullable>",
  "<Nullable>enable</Nullable>\n    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>")
s = s.replace("</Project>", """  <ItemGroup>
    <PackageReference Include="CredProx" />
    <PackageReference Include="CredProx.Azure" />
    <PackageReference Include="Yarp.ReverseProxy" />
    <PackageReference Include="Azure.Identity" />
  </ItemGroup>
</Project>""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record drift FAIL "csproj rewrite"; return; }
  (cd "$d" && dotnet restore > restore.log 2>&1)
  local rcode=$?
  local nu
  nu=$(grep -oE 'NU[0-9]+' "$d/restore.log" | sort | uniq -c | tr '\n' ' ')
  if [ $rcode -ne 0 ]; then
    cp "$d/restore.log" "$d/restore-failure.log"
    record drift FAIL "restore: ${nu:-no NU code} (see $d/restore.log)"
    return
  fi
  build_warnaserror "$d"
  local bcode=$?
  local azurecore
  azurecore=$(cd "$d" && NO_COLOR=1 dotnet nuget why app.csproj Azure.Core 2>/dev/null | grep -oE 'Azure\.Core \(v[0-9.]+\)' | sort -u | tr '\n' ' ')
  if [ $bcode -eq 0 ]; then
    record drift PASS "CPM+warnaserror restore+build; NU codes: ${nu:-none}; Azure.Core graph: ${azurecore:-?}"
  else
    record drift FAIL "build -warnaserror: ${nu:-} (see $d/build.log); Azure.Core: ${azurecore:-?}"
  fi
}

cell_auth() {
  local d=$SCRATCH/auth
  scaffold_web "$d"
  add_credprox_pkg "$d" CredProx || { record auth FAIL "package add"; return; }
  # an app that already does ASP.NET auth + custom middleware: does the proxy still work,
  # does middleware ordering survive?
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
tail3 = "var app = builder.Build();\napp.MapReverseProxy();\napp.Run();\n"
assert tail3 in s, "scaffold tail not found"
s = s.replace(tail3, """builder.Services.AddAuthentication("always-ok")
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, AlwaysOkHandler>("always-ok", null);
builder.Services.AddAuthorization();
var app = builder.Build();

// ASP.NET's own pipeline order, with CredProx mounted after auth — the documented host order.
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (context, next) =>
{
    context.Request.Headers["X-Consumer-Middleware"] = "ran";
    await next();
});
app.MapReverseProxy();
app.Run();

// Marker handler: proves the auth pipeline authenticated the request the proxy forwards.
public sealed class AlwaysOkHandler : Microsoft.AspNetCore.Authentication.AuthenticationHandler<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions>
{
    public AlwaysOkHandler(Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger, System.Text.Encodings.Web.UrlEncoder encoder)
        : base(options, logger, encoder) { }
    protected override System.Threading.Tasks.Task<Microsoft.AspNetCore.Authentication.AuthenticateResult> HandleAuthenticateAsync()
        => System.Threading.Tasks.Task.FromResult(Microsoft.AspNetCore.Authentication.AuthenticateResult.Success(
            new Microsoft.AspNetCore.Authentication.AuthenticationTicket(
                new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity("always-ok")), "always-ok")));
}
""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record auth FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record auth FAIL "build, see $d/build.log"; return; }
  start_wiremock || { record auth FAIL "wiremock start"; return; }
  if smoke_web "$d"; then
    if curl_check_mw "$d"; then record auth PASS "auth+middleware ordering holds, smoke green"; else record auth FAIL "middleware marker absent upstream"; fi
  else record auth FAIL "smoke (see $d/run.log)"; fi
  stop_wiremock
}

# after smoke_web's own checks, one more request proving X-Consumer-Middleware reaches upstream
curl_check_mw() {
  # smoke_web's run already proved the journal side; this proves the consumer's own
  # middleware marker reaches the upstream: journal entry must name the header.
  local dir=$1
  curl -sf http://localhost:8088/__admin/requests 2>/dev/null | grep -q 'X-Consumer-Middleware'
}

# --- multi-package add-on cells (ADR-0005) ----------------------------------------
# The add-ons ship only in the locally built artifacts/packages feed until the next
# release, so these cells restore from that directory through their own NuGet.config
# (write_local_feed_config): no remote source is asked for a package id it has never
# carried.

add_local_feed() { # dir — the repo's built feed, and nothing else (see write_local_feed_config)
  local dir=$1
  write_local_feed_config "$dir"
}

keys_smoke() { # cellid dir — valid key 200, missing and wrong key 401, key value never upstream
  local id=$1 d=$2 pid code nocode badcode journal
  run_app "$d"
  pid=$!
  for _ in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || { kill "$pid" 2>/dev/null; record "$id" FAIL "proxy exited early (see $d/run.log)"; return 1; }
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-CredProx-Key: consumer-keys-cell' \
      http://127.0.0.1:5080/echo/headers 2>/dev/null || true)
    [ "$code" = "200" ] && break
    sleep 1
  done
  nocode=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5080/echo/headers 2>/dev/null || true)
  badcode=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-CredProx-Key: wrong-value-entirely' \
    http://127.0.0.1:5080/echo/headers 2>/dev/null || true)
  journal=$(curl -sf http://localhost:8088/__admin/requests 2>/dev/null || true)
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  if [ "$code" != "200" ]; then record "$id" FAIL "valid key got $code (see $d/run.log)"; return 1; fi
  if [ "$nocode" != "401" ] || [ "$badcode" != "401" ]; then
    record "$id" FAIL "missing key got $nocode, wrong key got $badcode, expected 401"; return 1
  fi
  if printf '%s' "$journal" | grep -q 'consumer-keys-cell'; then
    record "$id" FAIL "caller key reached the upstream journal"; return 1
  fi
  return 0
}

cell_keys() {
  local d=$SCRATCH/keys
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx || { record keys FAIL "package add"; return; }
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
entry = "builder.Services.AddCredProx(builder.Configuration);"
assert entry in s, "scaffold entry call not found"
s = s.replace(entry, """builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
{
    ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
    ["CredProx:Callers:app-a:Keys:0:KeyHash"] =
        "sha256:ede2d53fa6c1f60d7bd8df67f87a9093931ac51ab01df64315f5f1fc88374003",
});
builder.Services.AddCredProx(builder.Configuration);""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record keys FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record keys FAIL "build, see $d/build.log"; return; }
  start_wiremock || { record keys FAIL "wiremock start"; return; }
  keys_smoke keys "$d" || { stop_wiremock; return; }
  stop_wiremock
  record keys PASS "core (caller keys armed from config by the entry): valid key 200, missing/wrong key 401, key value never upstream"
}

cell_keytokens() {
  local d=$SCRATCH/keytokens
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx CredProx.Identity \
    || { record keytokens FAIL "package add"; return; }
  # One host with BOTH caller schemes: keys armed by the entry, the token scheme by the
  # chained Identity call. The shared caller policy must arrive once and the key path
  # must still work with the token scheme registered alongside.
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
entry = "builder.Services.AddCredProx(builder.Configuration);"
assert entry in s, "scaffold entry call not found"
s = s.replace(entry, """builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
{
    ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
    ["CredProx:Callers:app-a:Keys:0:KeyHash"] =
        "sha256:ede2d53fa6c1f60d7bd8df67f87a9093931ac51ab01df64315f5f1fc88374003",
    ["CredProx:CallerToken:Authority"] = "https://issuer.invalid/",
    ["CredProx:CallerToken:Audience"] = "consumer-compat",
});
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity();""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record keytokens FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record keytokens FAIL "build, see $d/build.log"; return; }
  start_wiremock || { record keytokens FAIL "wiremock start"; return; }
  keys_smoke keytokens "$d" || { stop_wiremock; return; }
  stop_wiremock
  record keytokens PASS "core+Identity: caller keys and the caller-token scheme coexist; key path green (token path not exercised)"
}

cell_hmac() {
  local d=$SCRATCH/hmac
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx || { record hmac FAIL "package add"; return; }
  cat > "$d/appsettings.json" << 'EOF'
{
  "CredProx": {
    "Destinations": { "sign": { "Template": "http://localhost:5080" } },
    "Credentials": {
      "signer": {
        "Type": "Hmac",
        "Secret": "secret:hmac-key",
        "Algorithm": "SHA256",
        "Encoding": "HexLower",
        "Components": [ "method", "path", "timestamp", "bodyHash" ],
        "Separator": "\n",
        "TimestampFormat": "UnixSeconds",
        "SignatureHeader": "X-Signature",
        "TimestampHeader": "X-Timestamp",
        "BufferBody": true,
        "MaxBodyBytes": 1048576
      },
      "signer-small": {
        "Type": "Hmac",
        "Secret": "secret:hmac-key",
        "Algorithm": "SHA256",
        "Encoding": "HexLower",
        "Components": [ "method", "path", "timestamp", "bodyHash" ],
        "Separator": "\n",
        "TimestampFormat": "UnixSeconds",
        "SignatureHeader": "X-Signature",
        "TimestampHeader": "X-Timestamp",
        "BufferBody": true,
        "MaxBodyBytes": 16
      }
    },
    "Secrets": { "hmac-key": "cc-shared-key" }
  },
  "ReverseProxy": {
    "Routes": {
      "api": {
        "ClusterId": "sign",
        "Match": { "Path": "/api/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/api" } ],
        "Metadata": { "CredProx.Destination": "sign", "CredProx.Credential": "signer" }
      },
      "small": {
        "ClusterId": "sign",
        "Match": { "Path": "/small/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/small" } ],
        "Metadata": { "CredProx.Destination": "sign", "CredProx.Credential": "signer-small" }
      }
    },
    "Clusters": {
      "sign": { "Destinations": { "sign": { "Address": "http://localhost:5080/" } } }
    }
  }
}
EOF
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
tail3 = "var app = builder.Build();\napp.MapReverseProxy();\napp.Run();\n"
assert tail3 in s, "scaffold tail not found"
s = s.replace(tail3, """var app = builder.Build();
// The stub vendor, same shape as samples/HmacSigning: an INDEPENDENT verifier of the
// documented canonical layout, sharing no code with CredProx.
app.Map("/verify", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync();
    var canonical = string.Join('\\n', context.Request.Method, context.Request.Path,
        context.Request.Headers["X-Timestamp"].ToString(),
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant());
    var expected = Convert.ToHexString(HMACSHA256.HashData(
        Encoding.UTF8.GetBytes("cc-shared-key"), Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    var ok = context.Request.Headers["X-Signature"].ToString() == expected;
    context.Response.StatusCode = ok ? 200 : 401;
    await context.Response.WriteAsync(ok ? "signature valid" : "signature invalid");
});
app.MapReverseProxy();
app.Run();
""")
s = "using System.Security.Cryptography;\nusing System.Text;\n" + s
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record hmac FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record hmac FAIL "build, see $d/build.log"; return; }
  run_app "$d"; local pid=$! detail="proxy never answered" signed overcap
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then detail="proxy exited early (see $d/run.log)"; break; fi
    signed=$(curl -sf -X POST -d '{"order":42}' http://127.0.0.1:5080/api/verify 2>/dev/null || true)
    # no -f here: the expected answer IS a 413, and curl -f would swallow the body and the -w line
    overcap=$(python3 -c "print('x'*100, end='')" | curl -s -X POST --data-binary @- -w '\nHTTP:%{http_code}' http://127.0.0.1:5080/small/verify 2>/dev/null || true)
    [ -n "$signed$overcap" ] && detail="verify/cap assertions not matched (see $d/run.log)"
    if printf '%s' "$signed" | grep -q 'signature valid' \
       && printf '%s' "$overcap" | grep -q 'credprox.body_too_large_to_sign' \
       && printf '%s' "$overcap" | grep -q 'HTTP:413'; then
      kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
      record hmac PASS "core (Hmac built into the entry): independent verifier accepted the signature, cap answered 413"
      return
    fi
    sleep 1
  done
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  record hmac FAIL "$detail"
}
cell_loginexchange() {
  local d=$SCRATCH/loginexchange
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx || { record loginexchange FAIL "package add"; return; }
  cat > "$d/appsettings.json" << 'EOF'
{
  "CredProx": {
    "Destinations": { "svc": { "Template": "http://localhost:5080" } },
    "Credentials": {
      "le": {
        "Type": "LoginExchange",
        "LoginEndpoint": "http://localhost:5080/login",
        "Method": "POST",
        "Form": { "User": "cc-svc", "Password": "secret:cc-password" },
        "Response": "JsonPath",
        "ResponseField": "sessionId",
        "DefaultLifetime": "01:00:00",
        "Partition": { "From": "header:X-API-Env", "Allowed": ["uat"] }
      }
    },
    "Secrets": { "cc-password": "demo-cc-password" }
  },
  "ReverseProxy": {
    "Routes": {
      "svc": {
        "ClusterId": "svc",
        "Match": { "Path": "/svc/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/svc" } ],
        "Metadata": { "CredProx.Destination": "svc", "CredProx.Credential": "le" }
      }
    },
    "Clusters": { "svc": { "Destinations": { "svc": { "Address": "http://localhost:5080/" } } } }
  }
}
EOF
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
tail3 = "var app = builder.Build();\napp.MapReverseProxy();\napp.Run();\n"
assert tail3 in s, "scaffold tail not found"
s = s.replace(tail3, """var app = builder.Build();
// The vendor stub: a login endpoint handing out a session for the right credentials,
// and a protected endpoint reporting only whether a session arrived — the password
// never leaves the proxy, and the session value never reaches the caller's echo.
// the form is read by hand: the minimal-API binder for a positional record answers
// 415 to a plain form POST in this template (no antiforgery metadata on the scaffold).
app.MapPost("/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var ok = form["User"] == "cc-svc" && form["Password"] == "demo-cc-password";
    return ok ? Results.Json(new { sessionId = "sess-cc-live" }) : Results.StatusCode(401);
});
app.Map("/echo", (HttpContext ctx) =>
    ctx.Request.Headers.Authorization.Count > 0 ? "auth-present" : "auth-missing");
app.MapReverseProxy();
app.Run();
""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record loginexchange FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record loginexchange FAIL "build, see $d/build.log"; return; }
  run_app "$d"; local pid=$! detail="proxy never answered" uat prod
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then detail="proxy exited early (see $d/run.log)"; break; fi
    uat=$(curl -sf -H 'X-API-Env: uat' http://127.0.0.1:5080/svc/echo 2>/dev/null || true)
    prod=$(curl -s -H 'X-API-Env: prod' http://127.0.0.1:5080/svc/echo -w '\nHTTP:%{http_code}' 2>/dev/null || true)
    [ -n "$uat$prod" ] && detail="partition assertions not matched (see $d/run.log)"
    if printf '%s' "$uat" | grep -q '^auth-present$' \
       && printf '%s' "$prod" | grep -q 'HTTP:400' \
       && printf '%s' "$prod" | grep -q 'credprox.partition_not_allowed'; then
      kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
      record loginexchange PASS "core (LoginExchange built into the entry): login session attached, blocked partition refused before any vendor call"
      return
    fi
    sleep 1
  done
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  record loginexchange FAIL "$detail"
}
cell_oauth() {
  local d=$SCRATCH/oauth
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx CredProx.Identity || { record oauth FAIL "package add"; return; }
  cat > "$d/appsettings.json" << 'EOF'
{
  "CredProx": {
    "Destinations": { "svc": { "Template": "http://localhost:5080" } },
    "Credentials": {
      "oa": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "http://localhost:5080/token",
        "ClientAuthentication": "FormPost",
        "ClientId": "cc-svc",
        "ClientSecret": "secret:cc-client-secret",
        "Scope": "cc-scope"
      },
      "bad": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "http://localhost:5080/token",
        "ClientAuthentication": "FormPost",
        "ClientId": "cc-svc",
        "ClientSecret": "secret:cc-wrong-secret",
        "Scope": "cc-scope"
      }
    },
    "Secrets": { "cc-client-secret": "demo-cc-secret", "cc-wrong-secret": "demo-wrong" }
  },
  "ReverseProxy": {
    "Routes": {
      "svc": {
        "ClusterId": "svc",
        "Match": { "Path": "/svc/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/svc" } ],
        "Metadata": { "CredProx.Destination": "svc", "CredProx.Credential": "oa" }
      },
      "bad": {
        "ClusterId": "svc",
        "Match": { "Path": "/bad/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/bad" } ],
        "Metadata": { "CredProx.Destination": "svc", "CredProx.Credential": "bad" }
      }
    },
    "Clusters": { "svc": { "Destinations": { "svc": { "Address": "http://localhost:5080/" } } } }
  }
}
EOF
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = s.replace("builder.Services.AddCredProx(builder.Configuration);",
              "builder.Services.AddCredProx(builder.Configuration)\n    .AddIdentity();")
tail3 = "var app = builder.Build();\napp.MapReverseProxy();\napp.Run();\n"
assert tail3 in s, "scaffold tail not found"
s = s.replace(tail3, """var app = builder.Build();
// The vendor stub: a token endpoint handing out a bearer token for the right client
// credentials, and a protected endpoint reporting only whether a token arrived — the
// client secret never leaves the proxy, and the token value never reaches the caller's
// echo. the form is read by hand: the minimal-API binder for a positional record answers
// 415 to a plain form POST in this template (no antiforgery metadata on the scaffold).
app.MapPost("/token", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var ok = form["grant_type"] == "client_credentials"
        && form["client_id"] == "cc-svc"
        && form["client_secret"] == "demo-cc-secret";
    return ok
        ? Results.Json(new { access_token = "cc-token-live", token_type = "Bearer", expires_in = 3600 })
        : Results.Json(new { error = "invalid_client" }, statusCode: 401);
});
app.Map("/echo", (HttpContext ctx) =>
    ctx.Request.Headers.Authorization.Count > 0 ? "auth-present" : "auth-missing");
app.MapReverseProxy();
app.Run();
""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record oauth FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record oauth FAIL "build, see $d/build.log"; return; }
  run_app "$d"; local pid=$! detail="proxy never answered" ok refused
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then detail="proxy exited early (see $d/run.log)"; break; fi
    ok=$(curl -sf http://127.0.0.1:5080/svc/echo 2>/dev/null || true)
    # no -f here: the expected answer IS a 502, and curl -f would swallow the body and the -w line
    refused=$(curl -s http://127.0.0.1:5080/bad/echo -w '\nHTTP:%{http_code}' 2>/dev/null || true)
    [ -n "$ok$refused" ] && detail="token/refusal assertions not matched (see $d/run.log)"
    if printf '%s' "$ok" | grep -q '^auth-present$' \
       && printf '%s' "$refused" | grep -q 'credprox.credential_unavailable' \
       && printf '%s' "$refused" | grep -q 'HTTP:502'; then
      kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
      record oauth PASS "core+CredProx.Identity: bearer token attached from the token endpoint, refused client answered 502 without reaching upstream"
      return
    fi
    sleep 1
  done
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  record oauth FAIL "$detail"
}
# core + CredProx.Operations: the consumer story of the operations split — the host
# configures Throttling, Resilience and Health and chains AddOperations() on the entry;
# the app boots (the startup refusal stays silent exactly when the features are
# registered), the static credential attaches through the throttle+resilience pipeline,
# and /health reports the credential probes' first round (which runs at startup).
cell_operations() {
  local d=$SCRATCH/operations
  scaffold_web "$d"
  add_local_feed "$d"
  add_credprox_pkg "$d" CredProx CredProx.Operations || { record operations FAIL "package add"; return; }
  cat > "$d/appsettings.json" << 'EOF'
{
  "CredProx": {
    "Destinations": { "svc": { "Template": "http://localhost:5080" } },
    "Credentials": {
      "echo-key": { "Type": "StaticKey", "Name": "X-API-Key", "Secret": "secret:echo-key" }
    },
    "Secrets": { "echo-key": "demo-echo-key" },
    "Throttling": { "PermitsPerInterval": 10, "Interval": "00:00:01" },
    "Resilience": { "MaxRetries": 1, "AttemptTimeout": "00:00:10" },
    "Health": { "Enabled": true, "ProbeInterval": "00:00:05" }
  },
  "ReverseProxy": {
    "Routes": {
      "svc": {
        "ClusterId": "svc",
        "Match": { "Path": "/svc/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/svc" } ],
        "Metadata": { "CredProx.Destination": "svc", "CredProx.Credential": "echo-key" }
      }
    },
    "Clusters": { "svc": { "Destinations": { "svc": { "Address": "http://localhost:5080/" } } } }
  }
}
EOF
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = s.replace("builder.Services.AddCredProx(builder.Configuration);",
              "builder.Services.AddCredProx(builder.Configuration)\n    .AddOperations();")
tail3 = "var app = builder.Build();\napp.MapReverseProxy();\napp.Run();\n"
assert tail3 in s, "scaffold tail not found"
s = s.replace(tail3, """var app = builder.Build();
app.MapHealthChecks("/health");
// The vendor stub: reports only whether the configured credential header arrived
// with the right value — the secret reference resolves inside the proxy.
app.Map("/echo", (HttpContext ctx) =>
    ctx.Request.Headers["X-API-Key"] == "demo-echo-key" ? "cred-present" : "cred-missing");
app.MapReverseProxy();
app.Run();
""")
p.write_text(s)
PYEOF
  [ $? -ne 0 ] && { record operations FAIL "program rewrite"; return; }
  build_warnaserror "$d" || { record operations FAIL "build, see $d/build.log"; return; }
  run_app "$d"; local pid=$! detail="proxy never answered" ok health
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then detail="proxy exited early (see $d/run.log)"; break; fi
    ok=$(curl -sf http://127.0.0.1:5080/svc/echo 2>/dev/null || true)
    health=$(curl -sf http://127.0.0.1:5080/health 2>/dev/null || true)
    [ -n "$ok$health" ] && detail="echo/health assertions not matched (see $d/run.log)"
    if printf '%s' "$ok" | grep -q '^cred-present$' \
       && printf '%s' "$health" | grep -q '^Healthy$'; then
      kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
      record operations PASS "core+CredProx.Operations: host wires throttle+resilience+health with one chained call, credential attached through the pipeline, health probes Healthy"
      return
    fi
    sleep 1
  done
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  record operations FAIL "$detail"
}
cell_container() {
  local d=$SCRATCH/container
  scaffold_web "$d"
  add_credprox_pkg "$d" CredProx || { record container FAIL "package add"; return; }
  # ContainerImageTag is tag-only (CONTAINER2007); the repo name goes in ContainerImageName.
  (cd "$d" && dotnet publish -c Release /t:PublishContainer /p:ContainerImageName=m32-consumer /p:ContainerImageTag=latest > publish.log 2>&1) \
    || { record container FAIL "PublishContainer, see $d/publish.log"; return; }
  docker rm -f m32-consumer >/dev/null 2>&1 || true
  start_wiremock || { record container FAIL "wiremock start"; return; }
  docker run -d --name m32-consumer --network host m32-consumer:latest >/dev/null
  local ok=0 i
  for i in $(seq 1 30); do
    curl -sf http://127.0.0.1:5080/echo/headers 2>/dev/null | grep -q redacted \
      && curl -sf http://localhost:8088/__admin/requests 2>/dev/null | grep -q demo-static-key && { ok=1; break; }
    sleep 1
  done
  docker rm -f m32-consumer >/dev/null 2>&1 || true
  stop_wiremock
  if [ "$ok" = 1 ]; then record container PASS "PublishContainer image runs, smoke green"; else record container FAIL "container smoke"; fi
}

cell_testing() {
  local d=$SCRATCH/testing
  rm -rf "$d" && mkdir -p "$d"
  (cd "$d" && dotnet new xunit -o . >/dev/null 2>&1) || { record testing FAIL "template"; return; }
  write_local_feed_config "$d"
  add_credprox_pkg "$d" CredProx.Testing || { record testing FAIL "package add"; return; }
  (cd "$d" && dotnet package add Microsoft.Extensions.TimeProvider.Testing >/dev/null 2>&1)
  # the conformance suite is [Experimental(CREDPROX001)] like the plugin contract —
  # a strict consumer suppresses exactly that id (recorded in the compat doc)
  sed -i 's|<Nullable>enable</Nullable>|<Nullable>enable</Nullable>\n    <NoWarn>$(NoWarn);CREDPROX001</NoWarn>|' "$d"/*.csproj
  cat > "$d/UnitTest1.cs" << 'EOF'
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using CredProx.Testing;
using Xunit;

namespace ConsumerTesting;

// A consumer exercising the documented conformance kit (plan 3.5) for their own
// credential provider: inherit the suite, describe the credential in configuration,
// and the no-secret-in-logs / failure-hygiene checks run through the real binder and
// secret scoping. The suite registers the type and serves the fake token server.
public sealed class MySessionProvider : ICredentialProvider<MySessionOptions>
{
    private readonly IHttpClientFactory _http;

    public MySessionProvider(IHttpClientFactory http) => _http = http;

    public string Type => "MySession";

    public async ValueTask<string> GetCredentialAsync(
        MySessionOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken)
    {
        var user = await secrets.GetSecretAsync(options.User!.Substring("secret:".Length), cancellationToken);
        var password = await secrets.GetSecretAsync(options.Password!.Substring("secret:".Length), cancellationToken);
        var response = await _http.CreateClient("credprox").PostAsync(
            options.LoginEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string> { ["user"] = user, ["password"] = password }),
            cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException($"Credential '{context.CredentialName}' of type MySession: no access_token.");
    }
}

public sealed class MySessionOptions
{
    public string? LoginEndpoint { get; set; }
    public string? User { get; set; }
    public string? Password { get; set; }
}

public sealed class MySessionConformance : CredentialProviderConformanceTests<MySessionProvider, MySessionOptions>
{
    private const string UserValue = "conformance-user";
    private const string PasswordValue = "conformance-password";

    protected override string CredentialTypeName => "MySession";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "MySession",
            ["LoginEndpoint"] = "https://vendor.example/login",
            ["User"] = "secret:user",
            ["Password"] = "secret:pass",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?> { ["user"] = UserValue, ["pass"] = PasswordValue };

    protected override IReadOnlyList<string> SecretValues { get; } = [UserValue, PasswordValue];
}
EOF
  build_warnaserror "$d" || { record testing FAIL "build, see $d/build.log"; return; }
  (cd "$d" && dotnet test --no-build > test.log 2>&1) || { record testing FAIL "test run, see $d/test.log"; return; }
  record testing PASS "CredProx.Testing conformance suite green in a consumer test project"
}

cell_trim() {
  # Measured this run, not support claims — see docs/consumer-compatibility.md:
  #  - CredProx web app, PublishTrimmed self-contained: publish completes; the ILLink summary
  #    flags 'Assembly CredProx produced trim warnings' (IL2104). Trimming: NOT supported.
  #  - Console app rooted at the CredProx entry points, PublishAot: native binary builds,
  #    zero IL diagnostics on that root set.
  local d=$SCRATCH/trim-web rc
  scaffold_web "$d"
  add_credprox_pkg "$d" CredProx || { record trim FAIL "package add (web)"; return; }
  (cd "$d" && dotnet publish -c Release -r linux-x64 -p:PublishTrimmed=true -p:SelfContained=true > trim.log 2>&1)
  rc=$?
  local flagged
  flagged=$(grep -oE "Assembly '[A-Za-z.]+' produced trim warnings" "$d/trim.log" | sed "s/Assembly '//;s/' produced trim warnings//" | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ $rc -ne 0 ]; then record trim FAIL "web PublishTrimmed publish, see $d/trim.log"; return; fi

  local a=$SCRATCH/trim-aot
  rm -rf "$a" && mkdir -p "$a"
  (cd "$a" && dotnet new console -o . >/dev/null 2>&1) || { record trim FAIL "console template"; return; }
  write_local_feed_config "$a"
  add_credprox_pkg "$a" CredProx || { record trim FAIL "package add (console)"; return; }
  sed -i 's|<Nullable>enable</Nullable>|<Nullable>enable</Nullable>\n    <NoWarn>$(NoWarn);CREDPROX001</NoWarn>|' "$a"/*.csproj
  # root the CredProx entry points so the linker analyses the library, not just the probe
  cat > "$a/Program.cs" << 'EOF'
_ = typeof(CredProx.CredProxAuth);
_ = typeof(CredProx.CredProxMetadata);
_ = typeof(CredProx.CredProxBuilder);
_ = typeof(Microsoft.Extensions.DependencyInjection.CredProxBuilderExtensions);
_ = typeof(Microsoft.Extensions.DependencyInjection.CredProxReverseProxyBuilderExtensions);
Console.WriteLine("trim-aot probe");
EOF
  (cd "$a" && dotnet publish -c Release -r linux-x64 -p:PublishAot=true > aot.log 2>&1)
  rc=$?
  local aotil aotbin
  aotil=$(grep -cE "(warning|error) IL[0-9]+" "$a/aot.log")
  aotbin=$(find "$a/bin/Release/net10.0/linux-x64/publish" -maxdepth 1 -type f -perm -u+x ! -name "*.json" ! -name "*.xml" 2>/dev/null | head -1)
  if [ $rc -ne 0 ] || [ -z "$aotbin" ] || [ ! -f "$aotbin" ]; then record trim FAIL "console PublishAot, see $a/aot.log"; return; fi
  record trim PASS "web trim: completes, flagged=[${flagged:-none}] (trimming NOT supported); console AOT: native binary, $aotil IL diagnostics"
}

# --- driver ----------------------------------------------------------------------

ALL_CELLS=(web webapi auth container net8 net9 drift testing trim keys keytokens hmac loginexchange oauth operations)
if [ "$#" -gt 0 ]; then CELLS=("$@"); else CELLS=("${ALL_CELLS[@]}"); fi
for c in "${CELLS[@]}"; do
  echo "-- cell $c"
  case "$c" in
    web) cell_web ;;
    webapi) cell_webapi ;;
    auth) cell_auth ;;
    container) cell_container ;;
    net8) cell_netframework net8 net8.0 ;;
    net9) cell_netframework net9 net9.0 ;;
    drift) cell_drift ;;
    trim) cell_trim ;;
    testing) cell_testing ;;
    keys) cell_keys ;;
    keytokens) cell_keytokens ;;
    hmac) cell_hmac ;;
    loginexchange) cell_loginexchange ;;
    oauth) cell_oauth ;;
    operations) cell_operations ;;
    *) echo "unknown cell $c" >&2; exit 2 ;;
  esac
done

echo "== results =="
cat "$RESULTS"
grep -q $'\tFAIL\t' "$RESULTS" && exit 1 || exit 0
