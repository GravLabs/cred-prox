using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the TokenExchange sample: real Keycloak (two users, KC_HOSTNAME
// issuer) and the StubApi downstream from the sample's own compose file — the downstream
// must sit in the compose network to agree on the advertised issuer — while the sample
// proxy runs as a host process. Everything the old smoke script did lives here.
[CollectionDefinition("TokenExchange")]
public sealed class TokenExchangeCollection : ICollectionFixture<TokenExchangeFixture>
{
}

public sealed class TokenExchangeFixture : IAsyncLifetime
{
    public const string CallerKey = "e14a7c3f9b2d48015ae6c8b4d7f29e53";
    public const string ProxyUrl = "http://localhost:5092";
    public const string ApiUrl = "http://localhost:5102";
    public const string KeycloakUrl = "http://localhost:5094";
    public const string StableIssuer = "http://keycloak:8080/realms/credprox";

    // Set only by the teardown cell: the URL the proxy host binds. An unroutable one
    // kills it while the compose stack is already up — the shape that forces init to
    // fail with resources alive, so cleanup (not a preflight message) is what decides.
    internal string? ProxyBindUrl { get; set; }

    // Set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private readonly StringBuilder _hostOutput = new();
    private readonly object _outputLock = new();
    private Process? _proxy;

    public HttpClient Proxy { get; } = new() { BaseAddress = new Uri(ProxyUrl) };
    public HttpClient Api { get; } = new() { BaseAddress = new Uri(ApiUrl) };

    public async Task InitializeAsync()
    {
        try
        {
            await InitCoreAsync();
        }
        catch
        {
            // A failed init must not leave the next run a victim: a half-started host
            // or compose stack keeps its ports and poisons later runs. Tear down
            // whatever exists (best effort), then surface the real failure.
            try
            {
                await DisposeAsync();
            }
            catch
            {
                // Cleanup failing is secondary; the init failure is the reportable one.
            }

            throw;
        }
    }

    private async Task InitCoreAsync()
    {
        (_repoRoot, _sampleBin) = LocateSampleBin();
        // down first: a leftover stack would trip the free-port check below.
        await RunComposeAsync("down");
        SmokePorts.EnsureFreeFor("TokenExchange");
        // Keycloak and the protected API run as containers — the API must resolve the
        // realm's advertised issuer URLs (KC_HOSTNAME), which only the compose network
        // provides. Only the proxy (the sample under test) runs as a host process.
        await RunComposeAsync("up", "-d", "--build", "keycloak", "api");
        await WaitForKeycloakAsync();
        await WaitForApiAsync();

        _proxy = StartProxy();

        // Readiness: alice's full path (caller key -> inbound validation -> exchange ->
        // downstream) must echo her through the exchanged token.
        var alice = await MintUserTokenAsync("alice");
        for (var attempt = 0; attempt < 90; attempt++)
        {
            if (_proxy.HasExited)
            {
                break;
            }

            try
            {
                var who = await WhoAsync(alice);
                if (who == "alice|credprox-proxy")
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // The proxy process exists but has not taken its port yet — a refused
                // connection is part of waiting for it, exactly as for the Keycloak and
                // api readiness loops above and below.
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(
            "the TokenExchange path never echoed alice|credprox-proxy within 90 s " +
            $"(proxyExited={_proxy.HasExited}).\n" +
            $"process output:\n{Tail()}");
    }

    public async Task<string> MintUserTokenAsync(string user)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "credprox-frontend",
            ["username"] = user,
            ["password"] = user,
        });
        using var client = new HttpClient();
        using var response = await client.PostAsync(
            $"{KeycloakUrl}/realms/credprox/protocol/openid-connect/token", form);
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("access_token").GetString()!;
    }

    // An attacker's HS256 JWT: the attacker's own secret, claims alice, the right
    // issuer and audience. CredProx must refuse it at signature validation, before
    // anything is exchanged.
    public string ForgeHs256Token()
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["sub"] = "alice",
            ["aud"] = "credprox-proxy",
            ["iss"] = StableIssuer,
            ["nbf"] = 0,
            ["iat"] = 0,
            ["exp"] = 9999999999,
        });
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("attacker-secret-0123456789abcdef01234")),
            SecurityAlgorithms.HmacSha256);
        return new JsonWebTokenHandler().CreateToken(payload, credentials);
    }

    public async Task<(int Status, string Body)> ProxyGetAsync(string bearer, bool withKey = true)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        if (withKey)
        {
            request.Headers.Add("X-CredProx-Key", CallerKey);
        }

        using var response = await Proxy.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    public async Task<(int Status, string Body)> ApiGetAsync(string bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        using var response = await Api.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private async Task<string> WhoAsync(string bearer)
    {
        var (status, body) = await ProxyGetAsync(bearer);
        return status == 200 ? body : string.Empty;
    }

    public async Task DisposeAsync()
    {
        if (_proxy is not null)
        {
            try
            {
                _proxy.Kill(entireProcessTree: true);
                await _proxy.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            _proxy.Dispose();
        }

        Proxy.Dispose();
        Api.Dispose();
        await RunComposeAsync("down");
    }

    private Process StartProxy()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "TokenExchange.dll"));
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        psi.Environment["ASPNETCORE_URLS"] = ProxyBindUrl ?? ProxyUrl;
        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the TokenExchange proxy host");
        process.OutputDataReceived += (_, e) => Append(e.Data);
        process.ErrorDataReceived += (_, e) => Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private (string RepoRoot, string SampleBin) LocateSampleBin()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var sampleBin = Path.Combine(repoRoot, "samples", "TokenExchange", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "TokenExchange.dll")))
        {
            throw new InvalidOperationException(
                $"no built TokenExchange host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "TokenExchange");
        var psi = new ProcessStartInfo { FileName = "docker", WorkingDirectory = sampleDir };
        psi.ArgumentList.Add("compose");
        psi.ArgumentList.Add("-f");
        psi.ArgumentList.Add(Path.Combine(sampleDir, "docker-compose.yml"));
        psi.ArgumentList.Add("-p");
        psi.ArgumentList.Add(ComposeProject.NameFor(_repoRoot));
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not run docker compose");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"docker compose {string.Join(' ', args)} failed (exit {process.ExitCode}): {stderr}{stdout}");
        }
    }

    private async Task WaitForKeycloakAsync()
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                using var ok = await probe.GetAsync(
                    $"{KeycloakUrl}/realms/credprox/.well-known/openid-configuration");
                if (ok.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Keycloak still starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("Keycloak never served its realm metadata within 90 s");
    }

    // Any HTTP answer from the API — even the 401 it must give a tokenless request —
    // means the container has taken its port.
    private async Task WaitForApiAsync()
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 60; attempt++)
        {
            try
            {
                await probe.GetAsync(ApiUrl + "/");
                return;
            }
            catch (HttpRequestException)
            {
                // container still building or starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("the protected API container never answered within 60 s");
    }

    private void Append(string? line)
    {
        if (line is null)
        {
            return;
        }

        lock (_outputLock)
        {
            _hostOutput.AppendLine(line);
        }
    }

    private string Tail()
    {
        lock (_outputLock)
        {
            var all = _hostOutput.ToString();
            return all.Length <= 2000 ? all : all[^2000..];
        }
    }
}
