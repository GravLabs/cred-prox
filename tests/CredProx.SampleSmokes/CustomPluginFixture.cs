using System.Diagnostics;
using System.Reflection;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the CustomPlugin sample: the vendor stand-in (StubApi, its own
// project) plus the plugin host. The demo app id and secret are the stand-in's own
// shipped defaults — nothing here is a real credential. StartHost stops the previous
// live host first, so cells never race over the sample's port.
[CollectionDefinition("CustomPlugin")]
public sealed class CustomPluginCollection : ICollectionFixture<CustomPluginFixture>
{
}

public sealed class CustomPluginFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5090";
    public const string StubUrl = "http://localhost:8094";
    public const string AppId = "demo-app";
    public const string VendorSecret = "demo-vendor-secret";
    public const string SessionId = "vsess_stub_session";

    private string _sampleBin = "";
    private string _stubBin = "";
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
        SmokePorts.EnsureFreeFor("CustomPlugin");

        _stub = StartProcess(_stubBin, "StubApi.dll", []);
        await WaitUntilAsync(async () =>
        {
            try
            {
                using var response = await Stub.GetAsync("/__logins");
                return response.IsSuccessStatusCode;
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

    /// <summary>
    /// Starts the plugin host pointed at the stand-in, replacing any live host from a
    /// previous cell. <paramref name="withSecret"/> off leaves the credential secret at
    /// its committed empty value — the bare-shipped-host state.
    /// </summary>
    public RunningHost StartHost(Dictionary<string, string>? extraEnv = null, bool withSecret = true)
    {
        StopLiveHosts();

        var env = new Dictionary<string, string>
        {
            ["CredProx__Credentials__vendor-session__LoginEndpoint"] = StubUrl + "/login",
            ["CredProx__Credentials__vendor-session__AppId"] = AppId,
            ["CredProx__Destinations__vendor__Template"] = StubUrl,
            ["ReverseProxy__Clusters__vendor__Destinations__vendor__Address"] = StubUrl + "/",
        };
        if (withSecret)
        {
            env["CredProx__Secrets__vendor-secret"] = VendorSecret;
        }

        if (extraEnv is not null)
        {
            foreach (var (key, value) in extraEnv)
            {
                env[key] = value;
            }
        }

        var process = StartProcess(_sampleBin, "CustomPlugin.dll", env);
        _liveHosts.Add(process);
        return new RunningHost(process);
    }

    /// <summary>
    /// Waits until the host answers HTTP at all (any status) on its port. The probe path
    /// is deliberately not a proxy route: readiness must not consume the login the cache
    /// cell counts.
    /// </summary>
    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        await WaitUntilAsync(async () =>
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the CustomPlugin host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
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
        }, "the CustomPlugin host never served its port within 90 s", seconds);
    }

    public async Task<int> LoginCallsAsync() => int.Parse(await Stub.GetStringAsync("/__logins"));

    /// <summary>
    /// Runs every [Fact] the plugin's conformance suite declares — the same facts a
    /// plugin author's own `dotnet test` runs, driven directly. Returns the failures.
    /// </summary>
    public static async Task<(int Total, string[] Failures)> RunConformanceSuiteAsync()
    {
        var suite = typeof(VendorSessionConformanceTests);
        var facts = suite
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null)
            .OrderBy(method => method.Name, StringComparer.Ordinal)
            .ToArray();

        var failures = new List<string>();
        foreach (var fact in facts)
        {
            // xunit's own contract: a fresh suite instance per fact.
            var instance = Activator.CreateInstance(suite)!;
            try
            {
                await (Task)fact.Invoke(instance, null)!;
            }
            catch (Exception ex)
            {
                var root = ex is TargetInvocationException wrapper ? wrapper.InnerException ?? ex : ex;
                failures.Add($"{fact.Name}: {root.Message.Split('\n')[0]}");
            }

            (instance as IDisposable)?.Dispose();
        }

        return (facts.Length, [.. failures]);
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

    private static async Task WaitUntilAsync(Func<Task<bool>> probe, string failure, int seconds = 90)
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
        var sampleBin = Path.Combine(repoRoot, "samples", "CustomPlugin", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "CustomPlugin", "StubApi", "bin", configuration, "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "CustomPlugin.dll")))
        {
            throw new InvalidOperationException(
                $"no built CustomPlugin host at '{sampleBin}' — build the sample first");
        }

        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built CustomPlugin stub at '{stubBin}' — build the sample first");
        }

        return (sampleBin, stubBin);
    }
}
