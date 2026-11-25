using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
namespace CredProx.SampleSmokes;
// The offline world of the FoundryLocalAgent sample: one stand-in process (StubApi)
// scripted by request content — the model arm replays the measured Foundry Local
// OpenAI shape including the thinking-model shape (empty content beside
// reasoning_content), the tools arm counts hits, the issuer arm serves the OIDC
// discovery documents — plus the gateway host and, run to completion per cell, the
// agent itself. The signing key is a throwaway RSA pair made per run: only its public
// half reaches the stub's /jwks, and the fixture mints short-lived caller tokens with
// the private one (the same test-token approach the AgentTokens smokes use) — nothing
// here is a real credential. StartHost stops the previous live host first, so cells
// never race over the sample's port.
[CollectionDefinition("FoundryLocalAgent")]
public sealed class FoundryLocalAgentCollection : ICollectionFixture<FoundryLocalAgentFixture>
{
}
public sealed class FoundryLocalAgentFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5107";
    public const string StubUrl = "http://localhost:8105";
    public const string IssuerUrl = StubUrl + "/issuer";
    public const string Audience = "credprox-local-agent";
    /// <summary>The demo client id the offline config lists for the agent caller — the
    /// azp every admitted cell token carries.</summary>
    public const string MappedClient = "local-agent-client";
    private const string GeneratedKid = "demo-local-agent-generated-1";
    private string _sampleBin = "";
    private string _stubBin = "";
    private string _agentBin = "";
    private RSA _signingKey = RSA.Create(2048);
    public DateTimeOffset Now { get; private set; }
    private readonly List<Process> _liveHosts = [];
    private Process? _stub;
    public HttpClient Stub { get; } = new() { BaseAddress = new Uri(StubUrl) };
    public async Task InitializeAsync()
    {
        try
        {
            await InitCoreAsync();
        }
        catch
        {
            // A failed init must not leave the next run a victim: a half-started host
            // keeps its ports and poisons later runs. Tear down whatever exists (best
            // effort), then surface the real failure.
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
        (_sampleBin, _stubBin, _agentBin) = LocateBins();
        SmokePorts.EnsureFreeFor("FoundryLocalAgent");
        _stub = StartProcess(_stubBin, "StubApi.dll", []);
        await WaitUntilAsync(async () =>
        {
            try
            {
                using var response = await Stub.GetAsync("/__modelcalls");
                return response.IsSuccessStatusCode;
            }
            catch (HttpRequestException)
            {
                return false; // still warming
            }
        }, "the agent stand-in never served its port");
        Now = DateTimeOffset.UtcNow;
        _signingKey = RSA.Create(2048);
        await PublishPublicKeyAsync();
    }
    public async Task DisposeAsync()
    {
        foreach (var process in _liveHosts.Concat([_stub]).Where(p => p is not null).Cast<Process>())
        {
            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }
            process.Dispose();
        }
        _liveHosts.Clear();
        _stub = null;
        Stub.Dispose();
    }
    /// <summary>A host process with its output drained into readable strings.</summary>
    public sealed class RunningHost
    {
        private readonly StringBuilder _stdout = new();
        private readonly StringBuilder _stderr = new();
        internal RunningHost(Process process)
        {
            Process = process;
            process.OutputDataReceived += (_, e) =>
            {
                lock (_stdout)
                {
                    _stdout.AppendLine(e.Data);
                }
            };
            process.ErrorDataReceived += (_, e) =>
            {
                lock (_stderr)
                {
                    _stderr.AppendLine(e.Data);
                }
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
        }
        public Process Process { get; }
        public string Stdout
        {
            get { lock (_stdout) { return _stdout.ToString(); } }
        }
        public string Stderr
        {
            get { lock (_stderr) { return _stderr.ToString(); } }
        }
    }
    /// <summary>
    /// Starts the gateway host pointed at the Foundry Local stand-in, replacing any live
    /// host from a previous cell. The shipped routes differ from the bare config only by
    /// the stand-in address; the token world — issuer at the same stub, the demo audience
    /// and the demo client id, RequireHttpsMetadata off for the loopback http issuer — is
    /// the offline mirror of appsettings.Development.json, so the cell's default world is
    /// the shipped one with stand-ins plugged in.
    /// </summary>
    public RunningHost StartHost(Dictionary<string, string>? extraEnv = null)
    {
        StopLiveHosts();
        var env = new Dictionary<string, string>
        {
            ["CredProx__Destinations__foundry__Template"] = StubUrl,
            ["ReverseProxy__Clusters__foundry__Destinations__foundry__Address"] = StubUrl + "/",
            ["CredProx__Destinations__docs-api__Template"] = StubUrl,
            ["ReverseProxy__Clusters__docs-api__Destinations__docs-api__Address"] = StubUrl + "/",
            ["CredProx__CallerToken__Authority"] = IssuerUrl,
            ["CredProx__CallerToken__Audience"] = Audience,
            ["CredProx__CallerToken__RequireHttpsMetadata"] = "false",
            ["CredProx__Callers__agent-app__TokenClientIds__0"] = MappedClient,
        };
        if (extraEnv is not null)
        {
            foreach (var (key, value) in extraEnv)
            {
                env[key] = value;
            }
        }
        var process = StartProcess(_sampleBin, "FoundryLocalAgent.dll", env);
        _liveHosts.Add(process);
        return new RunningHost(process);
    }
    /// <summary>
    /// Waits until the host answers HTTP at all (any status) on its port. The probe path
    /// is deliberately not a proxy route: readiness must not authenticate or move the
    /// stand-in's hit counter.
    /// </summary>
    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        await WaitUntilAsync(async () =>
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the FoundryLocalAgent host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
            }
            try
            {
                using var ok = await probe.GetAsync(HostUrl + "/readiness-probe");
                return true;
            }
            catch (HttpRequestException)
            {
                return false; // still warming
            }
        }, "the FoundryLocalAgent host never served its port within 90 s", seconds);
    }
    public async Task<int> ModelCallsAsync() => int.Parse(await Stub.GetStringAsync("/__modelcalls"));
    public async Task<int> DocsAsync() => int.Parse(await Stub.GetStringAsync("/__docs"));
    public async Task<int> AdminAsync() => int.Parse(await Stub.GetStringAsync("/__admin"));
    /// <summary>Hand the stub issuer this run's PUBLIC key only — the /jwks list the
    /// host's real OIDC pipeline discovers. The private half never leaves here.</summary>
    private async Task PublishPublicKeyAsync()
    {
        var rsaPublic = _signingKey.ExportParameters(includePrivateParameters: false);
        var publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = "RS256",
            ["kid"] = GeneratedKid,
            ["n"] = Base64UrlEncoder.Encode(rsaPublic.Modulus!),
            ["e"] = Base64UrlEncoder.Encode(rsaPublic.Exponent!),
        };
        using var response = await Stub.PostAsync(
            "/__publishjwk",
            new StringContent(JsonSerializer.Serialize(publicJwk), Encoding.UTF8, "application/json"));
        response.EnsureSuccessStatusCode();
    }
    /// <summary>One short-lived caller token, signed by this run's throwaway key — the
    /// same test-token shape the AgentTokens smokes mint: azp carries the client id,
    /// roles name the admitted operations, iat/exp sit around the shared clock anchor.</summary>
    public string Issue(string azp, string[] roles, string uti)
    {
        var payload = new Dictionary<string, object>
        {
            ["iss"] = IssuerUrl,
            ["aud"] = Audience,
            ["azp"] = azp,
            ["uti"] = uti,
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["roles"] = roles,
        };
        var credentials = new SigningCredentials(
            new RsaSecurityKey(_signingKey) { KeyId = GeneratedKid },
            SecurityAlgorithms.RsaSha256);
        return new JsonWebTokenHandler().CreateToken(JsonSerializer.Serialize(payload), credentials);
    }
    /// <summary>The agent's ordinary world: the mapped demo client naming both shipped
    /// rules (model-call, docs-read) — everything the agent does is admitted.</summary>
    public string IssueAgentToken(string uti) => Issue(MappedClient, ["model-call", "docs-read"], uti);
    public static async Task WaitUntilAsync(Func<Task<bool>> probe, string failure, int seconds = 30)
    {
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (await probe())
            {
                return;
            }
            await Task.Delay(1000);
        }
        throw new InvalidOperationException(failure);
    }
    private void StopLiveHosts()
    {
        foreach (var host in _liveHosts)
        {
            try
            {
                host.Kill(entireProcessTree: true);
                host.WaitForExit();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }
            host.Dispose();
        }
        _liveHosts.Clear();
    }
    private static Process StartProcess(string bin, string dll, Dictionary<string, string> env)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = bin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(bin, dll));
        foreach (var (key, value) in env)
        {
            psi.Environment[key] = value;
        }
        return Process.Start(psi) ?? throw new InvalidOperationException($"could not start {dll}");
    }
    private static (string SampleBin, string StubBin, string AgentBin) LocateBins()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }
        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var configuration = parts[binIndex + 1];
        var sampleBin = Path.Combine(repoRoot, "samples", "FoundryLocalAgent", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "FoundryLocalAgent", "StubApi", "bin", configuration, "net10.0");
        var agentBin = Path.Combine(repoRoot, "samples", "FoundryLocalAgent", "Agent", "bin", configuration, "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "FoundryLocalAgent.dll")))
        {
            throw new InvalidOperationException(
                $"no built FoundryLocalAgent host at '{sampleBin}' — build the sample first");
        }
        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built FoundryLocalAgent stub at '{stubBin}' — build the sample first");
        }
        if (!File.Exists(Path.Combine(agentBin, "LocalAgent.dll")))
        {
            throw new InvalidOperationException(
                $"no built agent at '{agentBin}' — build the sample first");
        }
        return (sampleBin, stubBin, agentBin);
    }
    /// <summary>
    /// Runs the agent to completion against the live host with the given caller token as
    /// AGENT_TOKEN, and returns its exit code and combined output. Timeouts are
    /// generous: a CPU-speed local model (or the offline stand-in standing in for one)
    /// is not a cloud endpoint.
    /// </summary>
    public async Task<(int ExitCode, string Output)> RunAgentAsync(
        string model, string token, int seconds = 120)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _agentBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_agentBin, "LocalAgent.dll"));
        psi.Environment["GatewayUrl"] = HostUrl;
        psi.Environment["AGENT_TOKEN"] = token;
        psi.Environment["Model"] = model;
        psi.Environment["TimeoutSeconds"] = "60";
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the agent");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var kill = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            await process.WaitForExitAsync(kill.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException($"the agent did not finish within {seconds} s");
        }
        return (process.ExitCode, await stdoutTask + await stderrTask);
    }
}
