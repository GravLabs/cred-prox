using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the AgentTokens sample: two WireMock stubs from the sample's own
// compose file, a signing key generated fresh in THIS process (the stub issuer learns only
// its public half, so no private material is ever committed), and the sample host itself
// running as a separate `dotnet exec` process with ASPNETCORE_ENVIRONMENT=Development —
// exactly how a developer runs the offline demo by hand. Everything the old in-process
// smoke harness did lives here instead of in the sample.
[CollectionDefinition("AgentTokens")]
public sealed class AgentTokensCollection : ICollectionFixture<AgentTokensFixture>
{
}

public sealed class AgentTokensFixture : IAsyncLifetime
{
    public const string GeneratedKid = "demo-agent-generated-1";
    public const string SampleUrl = "http://localhost:5096";
    public const string IssuerUrl = "http://localhost:8085";
    public const string UpstreamUrl = "http://localhost:8086";

    // All three are set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private string _agentBin = "";
    private readonly StringBuilder _hostOutput = new();
    private readonly object _outputLock = new();
    private Process? _sample;
    private RSA? _signingKey;

    public HttpClient Sample { get; } = new() { BaseAddress = new Uri(SampleUrl) };
    public HttpClient IssuerAdmin { get; } = new() { BaseAddress = new Uri(IssuerUrl) };
    public HttpClient UpstreamAdmin { get; } = new() { BaseAddress = new Uri(UpstreamUrl) };

    // One wall-clock anchor for every token in the run, as the old smoke had: freshness is
    // relative to this instant, so the staleness cell stays deterministic.
    public DateTimeOffset Now { get; private set; }

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
        (_repoRoot, _sampleBin, _agentBin) = LocateSampleBin();
        Now = DateTimeOffset.UtcNow;

        // down first: a leftover stack from an earlier run would carry a stale request
        // journal (and a stale key) into these cells, and its ports would fail the
        // free-port check.
        await RunComposeAsync("down");
        SmokePorts.EnsureFreeFor("AgentTokens");
        await RunComposeAsync("up", "-d");
        await WaitForStubAsync(IssuerAdmin);
        await WaitForStubAsync(UpstreamAdmin);

        _signingKey = RSA.Create(2048);
        await RegisterPublicKeyAsync();

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "AgentTokens.dll"));
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        // The metering opt-in cell reads the usage counters off this host's console exporter,
        // so the exporter must print on a 1 s cadence — its 60 s default outlasts the whole
        // offline loop.
        psi.Environment["Metrics__Console"] = "true";
        psi.Environment["OTEL_METRIC_EXPORT_INTERVAL"] = "1000";
        _sample = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the AgentTokens host");
        _sample.OutputDataReceived += (_, e) => Append(e.Data);
        _sample.ErrorDataReceived += (_, e) => Append(e.Data);
        _sample.BeginOutputReadLine();
        _sample.BeginErrorReadLine();

        // Readiness: an unauthenticated GET must reach the pipeline and be refused — that
        // proves the host is up AND enforcing, before any cell starts.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 30; attempt++)
        {
            if (_sample.HasExited)
            {
                break;
            }

            try
            {
                var response = await probe.GetAsync($"{SampleUrl}/docs/readme");
                if ((int)response.StatusCode == 401)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // still binding its sockets
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(
            $"the AgentTokens host never served the expected 401 within 30 s " +
            $"(exited={_sample.HasExited}, exitCode={(_sample.HasExited ? _sample.ExitCode.ToString() : "n/a")}).\n" +
            $"host output:\n{Tail()}");
    }

    public async Task<HttpResponseMessage> RegisterPublicKeyAsync()
    {
        var rsaPublic = _signingKey!.ExportParameters(includePrivateParameters: false);
        var publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = "RS256",
            ["kid"] = GeneratedKid,
            ["n"] = Base64UrlEncoder.Encode(rsaPublic.Modulus!),
            ["e"] = Base64UrlEncoder.Encode(rsaPublic.Exponent!),
        };
        return await IssuerAdmin.PostAsync(
            "/__admin/mappings",
            new StringContent(
                JsonSerializer.Serialize(new
                {
                    priority = 0,
                    request = new { method = "GET", urlPath = "/jwks" },
                    response = new
                    {
                        status = 200,
                        headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                        jsonBody = new { keys = new[] { publicJwk } },
                    },
                }),
                Encoding.UTF8,
                "application/json"));
    }

    // The same token shape the sample's old smoke minted: issuer/audience from the offline
    // config, azp for the caller mapping, iat for MaxTokenAge, roles as string or array.
    public string Issue(string azp, object? roles, DateTimeOffset issuedAt, string uti)
    {
        var payload = new Dictionary<string, object>
        {
            ["iss"] = IssuerUrl,
            ["aud"] = "credprox-agent-api",
            ["azp"] = azp,
            ["uti"] = uti,
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
        };
        if (roles is not null)
        {
            payload["roles"] = roles;
        }

        var credentials = new SigningCredentials(
            new RsaSecurityKey(_signingKey!) { KeyId = GeneratedKid },
            SecurityAlgorithms.RsaSha256);
        return new JsonWebTokenHandler().CreateToken(JsonSerializer.Serialize(payload), credentials);
    }

    public async Task<int> GetWithTokenAsync(string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/docs/readme");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        using var response = await Sample.SendAsync(request);
        return (int)response.StatusCode;
    }

    public async Task DisposeAsync()
    {
        if (_sample is not null)
        {
            try
            {
                _sample.Kill(entireProcessTree: true);
                await _sample.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            _sample.Dispose();
        }

        _signingKey?.Dispose();
        Sample.Dispose();
        IssuerAdmin.Dispose();
        UpstreamAdmin.Dispose();
        await RunComposeAsync("down");
    }

    // Runs the sample's agent client as a separate process with NOTHING but its Entra
    // token in the environment — exactly how a developer runs the demo. Returns exit code
    // and merged stdout+stderr so cells can assert the transcript AND the leak scan.
    public async Task<(int Exit, string Output)> RunAgentAsync(string token)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _agentBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_agentBin, "Agent.dll"));
        psi.Environment["CREDPROX_URL"] = SampleUrl;
        psi.Environment["AGENT_TOKEN"] = token;
        using var agent = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the AgentTokens agent");
        var stdoutTask = agent.StandardOutput.ReadToEndAsync();
        var stderrTask = agent.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try
        {
            await agent.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            agent.Kill(entireProcessTree: true);
            throw new InvalidOperationException(
                $"the agent never finished within 60 s. output so far:\n{await stdoutTask}\n{await stderrTask}");
        }

        return (agent.ExitCode, $"{await stdoutTask}\n{await stderrTask}");
    }

    // The scripted provider chain is a state machine on the upstream stub; every cell
    // that runs the full agent loop needs it back at "Started". The request journal is
    // cleared with it so a cell that counts journal records sees only its own loop
    // (the DELETE /__admin/requests house pattern, cf. CallerApiKeyFixture).
    public async Task ResetProviderScenariosAsync()
    {
        using var response = await UpstreamAdmin.PostAsync("/__admin/scenarios/reset", new StringContent(""));
        response.EnsureSuccessStatusCode();
        using var clear = await UpstreamAdmin.DeleteAsync("/__admin/requests");
        clear.EnsureSuccessStatusCode();
    }

    // A snapshot of everything the sample host has printed so far (stdout and stderr).
    public string HostOutput()
    {
        lock (_outputLock)
        {
            return _hostOutput.ToString();
        }
    }

    // Read the latest console-exporter value of a counter instrument: the shipped exporter's
    // "Metric Name: <instrument>" line followed by its FIRST "Value:" line within the next
    // 1200 chars; "Value: Sum:" (histogram) and a missing record both answer -1. This is a
    // deliberate clone of the live suite's LiveHosts.CounterValue — that copy is pinned
    // byte-for-byte against captured exporter bytes by LiveHostsCounterParseTests, so marker
    // drift fails loudly THERE first. -1 is a failing read, never a value and never a pass.
    public static long CounterValue(string stdout, string instrument)
    {
        var marker = "Metric Name: " + instrument;
        var at = stdout.LastIndexOf(marker, StringComparison.Ordinal);
        if (at < 0)
        {
            return -1;
        }

        var window = stdout[at..Math.Min(at + 1200, stdout.Length)];
        var valueAt = window.IndexOf("Value:", StringComparison.Ordinal);
        if (valueAt < 0)
        {
            return -1;
        }

        var match = Regex.Match(window[valueAt..], @"^Value:\s*(\d+)");
        return match.Success ? long.Parse(match.Groups[1].Value) : -1;
    }

    // Wait until the console exporter has printed a non-zero value for every named instrument
    // (up to 30 s at 1 s polls — this host's exporter cadence is 1 s). On timeout the throw
    // carries the host output tail, so a RED cell shows what the exporter actually printed
    // instead of silently reading -1.
    public async Task WaitUntilMeteredAsync(params string[] instruments)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            var output = HostOutput();
            if (instruments.All(i => CounterValue(output, i) > 0))
            {
                return;
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(
            $"the console exporter never printed a non-zero value for {string.Join(", ", instruments)} within 30 s; "
            + $"host output:\n{Tail()}");
    }

    private (string RepoRoot, string SampleBin, string AgentBin) LocateSampleBin()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var sampleBin = Path.Combine(repoRoot, "samples", "AgentTokens", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "AgentTokens.dll")))
        {
            throw new InvalidOperationException(
                $"no built AgentTokens host at '{sampleBin}' — build the sample first");
        }

        var agentBin = Path.Combine(repoRoot, "samples", "AgentTokens", "Agent", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(agentBin, "Agent.dll")))
        {
            throw new InvalidOperationException(
                $"no built AgentTokens agent at '{agentBin}' — build samples/AgentTokens/Agent first");
        }

        return (repoRoot, sampleBin, agentBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "AgentTokens");
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

    private static async Task WaitForStubAsync(HttpClient admin)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                if ((await admin.GetAsync("/__admin/mappings")).IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // the stub is still starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException($"stub at {admin.BaseAddress} never served __admin/mappings within 30 s");
    }

    private void Append(string? line)
    {
        if (line is not null)
        {
            lock (_outputLock)
            {
                _hostOutput.AppendLine(line);
            }
        }
    }

    private string Tail()
    {
        lock (_outputLock)
        {
            return _hostOutput.ToString();
        }
    }
}
