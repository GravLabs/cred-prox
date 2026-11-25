using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the AzureOpenAI sample: the Entra-only Azure OpenAI stand-in
// (StubApi, its own project — it issues a canned Entra-shaped token on the managed-identity
// endpoint, serves chat only to that bearer, and refuses api-key) plus the gateway host.
// The demo caller keys are the sample's own shipped constants — nothing here is a real
// credential. Two guardrails make this a real offline world rather than a fake green:
// AZURE_POD_IDENTITY_AUTHORITY_HOST steers the host's DefaultAzureCredential chain to the
// stand-in, and the child PATH is fronted by a failing fake `az` so a broken seam can never
// fall through to a live az sign-in on this machine. StartHost stops the previous live host
// first, so cells never race over the sample's port.
[CollectionDefinition("AzureOpenAI")]
public sealed class AzureOpenAICollection : ICollectionFixture<AzureOpenAIFixture>
{
}

public sealed class AzureOpenAIFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5108";
    public const string StubUrl = "http://localhost:8106";
    public const string ChatAppKey = "azureopenai-demo-chat-key-1";
    public const string AdminAppKey = "azureopenai-demo-admin-key-1";

    // The bearer the stand-in's managed-identity endpoint issues; the cells require exactly
    // this value at the chat endpoint — "some bearer" would also pass on a real token.
    public const string CannedBearerToken = "aoai-offline-canned-bearer-token";

    private string _sampleBin = "";
    private string _stubBin = "";
    private string _azBlockerDir = "";
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
        (_sampleBin, _stubBin, _azBlockerDir) = LocateBins();
        SmokePorts.EnsureFreeFor("AzureOpenAI");
        _stub = StartProcess(_stubBin, "StubApi.dll", []);
        await WaitUntilAsync(async () =>
        {
            try
            {
                using var response = await Stub.GetAsync("/__calls");
                return response.IsSuccessStatusCode;
            }
            catch (HttpRequestException)
            {
                return false; // still warming
            }
        }, "the Azure OpenAI stand-in never served its port");
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

    /// <summary>
    /// Starts the sample host pointed at the stand-in: destination and cluster address
    /// repoint to it, and the Entra chain is steered to its managed-identity endpoint with
    /// the failing fake <c>az</c> fronting PATH so nothing can reach a real tenant.
    /// </summary>
    public RunningHost StartHost(Dictionary<string, string>? extraEnv = null)
    {
        StopLiveHosts();
        var env = new Dictionary<string, string>
        {
            ["CredProx__Destinations__azureopenai__Template"] = StubUrl,
            ["ReverseProxy__Clusters__azureopenai__Destinations__azureopenai__Address"] = StubUrl + "/",
            ["AZURE_POD_IDENTITY_AUTHORITY_HOST"] = StubUrl,
            ["PATH"] = _azBlockerDir + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH"),
        };
        if (extraEnv is not null)
        {
            foreach (var (key, value) in extraEnv)
            {
                env[key] = value;
            }
        }

        var process = StartProcess(_sampleBin, "AzureOpenAI.dll", env);
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
                    $"the AzureOpenAI host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
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
        }, "the AzureOpenAI host never served its port within 90 s", seconds);
    }

    public async Task<int> CallsAsync() => int.Parse(await Stub.GetStringAsync("/__calls"));

    /// <summary>The headers of the stand-in's last chat-completions attempt.</summary>
    public async Task<JsonElement> LastChatAttemptAsync()
        => JsonDocument.Parse(await Stub.GetStringAsync("/__last")).RootElement.Clone();

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

    private static (string SampleBin, string StubBin, string AzBlockerDir) LocateBins()
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
        var sampleBin = Path.Combine(repoRoot, "samples", "AzureOpenAI", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "AzureOpenAI", "StubApi", "bin", configuration, "net10.0");
        var azBlockerDir = Path.Combine(repoRoot, "tests", "CredProx.SampleSmokes", "testassets", "az-blocker");
        if (!File.Exists(Path.Combine(sampleBin, "AzureOpenAI.dll")))
        {
            throw new InvalidOperationException(
                $"no built AzureOpenAI host at '{sampleBin}' — build the sample first");
        }

        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built AzureOpenAI stub at '{stubBin}' — build the sample first");
        }

        if (!File.Exists(Path.Combine(azBlockerDir, "az")))
        {
            throw new InvalidOperationException(
                $"no az blocker at '{azBlockerDir}' — the offline guard must exist before any cell runs");
        }

        return (sampleBin, stubBin, azBlockerDir);
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
}
