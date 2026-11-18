using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the GitHub App sample: the GitHub stand-in (StubApi, its own
// project) plus the sample host, driven with a generated RSA pair — the private key
// reaches the host as its credential secret, the public key reaches the stand-in as its
// verifier. Neither key is committed or printed; the installation token is the stand-in's
// own demo value. StartHost stops the previous live host first, so cells never race
// over the sample's port.
[CollectionDefinition("GitHubApp")]
public sealed class GitHubAppCollection : ICollectionFixture<GitHubAppFixture>
{
}

public sealed class GitHubAppFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5081";
    public const string StubUrl = "http://localhost:8093";
    public const string InstallationToken = "ghs_stub_installation";

    private string _sampleBin = "";
    private string _stubBin = "";
    private readonly List<Process> _liveHosts = [];
    private Process? _stub;

    public string SigningKeyPem { get; private set; } = "";
    public string OtherSigningKeyPem { get; private set; } = "";

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
        SmokePorts.EnsureFreeFor("GitHubApp");

        using var appKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        SigningKeyPem = appKey.ExportPkcs8PrivateKeyPem();
        OtherSigningKeyPem = otherKey.ExportPkcs8PrivateKeyPem();

        _stub = StartProcess(_stubBin, "StubApi.dll", new Dictionary<string, string>
        {
            ["Stub__SigningKey"] = appKey.ExportSubjectPublicKeyInfoPem(),
        });
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
        }, "the GitHub stand-in never served its port");
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
    /// Starts the sample host pointed at the stand-in, replacing any live host from a
    /// previous cell. <paramref name="withSigningKey"/> off leaves the credential secret
    /// empty — the bare-shipped-host state an operator hits before setting the key.
    /// </summary>
    public RunningHost StartHost(Dictionary<string, string>? extraEnv = null, bool withSigningKey = true)
    {
        StopLiveHosts();

        var env = new Dictionary<string, string>
        {
            ["CredProx__Destinations__github__Template"] = StubUrl,
            ["CredProx__Credentials__github-app__TokenEndpoint"] = StubUrl + "/app/installations/789012/access_tokens",
            ["ReverseProxy__Clusters__github__Destinations__github__Address"] = StubUrl + "/",
        };
        if (withSigningKey)
        {
            env["CredProx__Secrets__github-app-signing-key"] = SigningKeyPem;
        }

        if (extraEnv is not null)
        {
            foreach (var (key, value) in extraEnv)
            {
                env[key] = value;
            }
        }

        var process = StartProcess(_sampleBin, "GitHubApp.dll", env);
        _liveHosts.Add(process);
        return new RunningHost(process);
    }

    /// <summary>
    /// Waits until the host answers HTTP at all (any status) on its port. The probe path
    /// is deliberately not a proxy route: readiness must not consume the token exchange
    /// that the cache cell counts.
    /// </summary>
    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        await WaitUntilAsync(async () =>
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the GitHubApp host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
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
        }, "the GitHubApp host never served its port within 90 s", seconds);
    }

    public async Task<int> TokenEndpointCallsAsync()
    {
        var text = await Stub.GetStringAsync("/__calls");
        return int.Parse(text);
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
        var sampleBin = Path.Combine(repoRoot, "samples", "GitHubApp", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "GitHubApp", "StubApi", "bin", configuration, "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "GitHubApp.dll")))
        {
            throw new InvalidOperationException(
                $"no built GitHubApp host at '{sampleBin}' — build the sample first");
        }

        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built GitHubApp stub at '{stubBin}' — build the sample first");
        }

        return (sampleBin, stubBin);
    }
}
