using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the AzureContainerApps sample: the vendor stand-in (StubApi, its
// own project) plus the gateway host on its bare shipped config — the config-secrets
// path. The demo caller key and the demo vendor key are the sample's own shipped
// constants; nothing here is a real credential. The Key Vault + managed identity path
// is the same three lines the shipped MicrosoftGraph sample runs, and the live harness
// (tools/aca-live-harness) proves it against the real provider. StartHost stops the
// previous live host first, so cells never race over the sample's port.
[CollectionDefinition("AzureContainerApps")]
public sealed class AzureContainerAppsCollection : ICollectionFixture<AzureContainerAppsFixture>
{
}

public sealed class AzureContainerAppsFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5097";
    public const string StubUrl = "http://localhost:8098";
    public const string CallerKey = "credprox-e17-aca-demo-key";

    /// <summary>The vendor key shipped in appsettings.json's demo Secrets block.</summary>
    public const string DemoVendorKey = "credprox-aca-demo-vendor-key-never-real";

    private string _sampleBin = "";
    private string _stubBin = "";
    private Process? _stub;
    private readonly List<Process> _liveHosts = [];

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
        (_sampleBin, _stubBin) = LocateBins();
        SmokePorts.EnsureFreeFor("AzureContainerApps");

        _stub = StartDotnet(_stubBin, "StubApi.dll", []);
        await WaitUntilAsync(async () =>
        {
            try
            {
                using var ok = await Stub.GetAsync("/__last-auth");
                return ok.IsSuccessStatusCode;
            }
            catch (HttpRequestException)
            {
                return false; // still warming
            }
        }, "the vendor stand-in never served its port");
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

    /// <summary>Starts the gateway host on its bare shipped config — no env overrides.</summary>
    public RunningHost StartHost()
    {
        StopLiveHosts();

        var process = StartDotnet(_sampleBin, "AzureContainerApps.dll", []);
        _liveHosts.Add(process);
        return new RunningHost(process);
    }

    /// <summary>
    /// Waits until the host answers HTTP at all (any status) on its port. The probe path
    /// is deliberately not a proxy route: readiness must not authenticate or reach out.
    /// </summary>
    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        await WaitUntilAsync(async () =>
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the AzureContainerApps host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
            }

            try
            {
                using var ok = await probe.GetAsync(HostUrl + "/health");
                return true;
            }
            catch (HttpRequestException)
            {
                return false; // still warming
            }
        }, "the AzureContainerApps host never served its port within 90 s", seconds);
    }

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

    private static Process StartDotnet(string bin, string dll, Dictionary<string, string> env)
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

    private static (string SampleBin, string StubBin) LocateBins()
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
        var sampleBin = Path.Combine(repoRoot, "samples", "AzureContainerApps", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "AzureContainerApps", "StubApi", "bin", configuration, "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "AzureContainerApps.dll")))
        {
            throw new InvalidOperationException(
                $"no built AzureContainerApps host at '{sampleBin}' — build the sample first");
        }

        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built AzureContainerApps stub at '{stubBin}' — build the sample first");
        }

        return (sampleBin, stubBin);
    }
}
