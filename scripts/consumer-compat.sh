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
# Cells:  web webapi auth container net8 net9 drift testing
# Results append to $M32_SCRATCH/results.tsv:  cell<TAB>PASS|FAIL<TAB>detail
#
# NO pipefail (early-exit grep would SIGPIPE the recorder); PASS/FAIL is recorded per
# cell and the exit code is non-zero if any cell fails.
set -u

FEED=${M32_FEED:-credprox}
VERSION=${M32_VERSION:-0.8.2}
SCRATCH=${M32_SCRATCH:-/tmp/m32-consumer-scratch}
RESULTS=$SCRATCH/results.tsv
REPO=${M32_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
WIREMOCK_IMAGE=wiremock/wiremock:3.9.2   # same stand-in as samples/QuickStart
export NUGET_PACKAGES=$SCRATCH/pkg
export DOTNET_CLI_TELEMETRY_OPTOUT=1

mkdir -p "$SCRATCH"
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

# The minimal-API host shape from samples/QuickStart (plan 6 E1), rebuilt here from
# packages only: static key credential, secret from configuration, /echo route.
scaffold_web() { # dir [extra-csproj-lines]
  local dir=$1 extra=${2:-}
  rm -rf "$dir" && mkdir -p "$dir"
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
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);
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
  # The machine's user-level NuGet config supplies the `credprox` source; a machine
  # without it fails restore and the cell records FAIL honestly. The URL never
  # appears in this file either way.
  local dir=$1; shift
  for p in "$@"; do
    (cd "$dir" && dotnet package add "$p" --version "$VERSION" >/dev/null) || return 1
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
  add_credprox_pkg "$d" CredProx || { record webapi FAIL "package add"; return; }
  # controllers stay; CredProx routes join them
  python3 - "$d/Program.cs" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
s = p.read_text()
s = s.replace("var app = builder.Build();", """builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);
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
    <PackageVersion Include="CredProx.AzureKeyVault" Version="VERSION" />
    <PackageVersion Include="Yarp.ReverseProxy" Version="2.3.0" />
    <PackageVersion Include="Azure.Identity" Version="1.17.0" />
  </ItemGroup>
</Project>
EOF
  sed -i "s/VERSION/$VERSION/g" "$d/Directory.Packages.props"
  # package source mapping by source KEY (URLs stay in the user-level config, never here):
  # this is the documented NU1507 fix for CPM consumers on a private feed plus nuget.org.
  cat > "$d/NuGet.config" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="credprox">
      <package pattern="CredProx*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
EOF
  python3 - "$d/app.csproj" << 'PYEOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = s.replace("<Nullable>enable</Nullable>",
  "<Nullable>enable</Nullable>\n    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>")
s = s.replace("</Project>", """  <ItemGroup>
    <PackageReference Include="CredProx" />
    <PackageReference Include="CredProx.AzureKeyVault" />
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
  add_credprox_pkg "$a" CredProx || { record trim FAIL "package add (console)"; return; }
  sed -i 's|<Nullable>enable</Nullable>|<Nullable>enable</Nullable>\n    <NoWarn>$(NoWarn);CREDPROX001</NoWarn>|' "$a"/*.csproj
  # root the CredProx entry points so the linker analyses the library, not just the probe
  cat > "$a/Program.cs" << 'EOF'
_ = typeof(CredProx.CredProxAuth);
_ = typeof(CredProx.CredProxMetadata);
_ = typeof(Microsoft.Extensions.DependencyInjection.CredProxServiceCollectionExtensions);
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

ALL_CELLS=(web webapi auth container net8 net9 drift testing trim)
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
    *) echo "unknown cell $c" >&2; exit 2 ;;
  esac
done

echo "== results =="
cat "$RESULTS"
grep -q $'\tFAIL\t' "$RESULTS" && exit 1 || exit 0
