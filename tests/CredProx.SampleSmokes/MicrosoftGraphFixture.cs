using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the MicrosoftGraph sample: a WireMock stand-in for Entra ID's
// token endpoint and for Graph itself (from the sample's own compose file), plus the
// sample host started per cell — the refusal cells need their own exit code and stderr,
// so the fixture hands out processes rather than owning one long-lived host.
[CollectionDefinition("MicrosoftGraph")]
public sealed class MicrosoftGraphCollection : ICollectionFixture<MicrosoftGraphFixture>
{
}

public sealed class MicrosoftGraphFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5085";
    public const string VendorUrl = "http://localhost:8092";
    public const string TokenPath = "/fake-tenant/oauth2/v2.0/token";

    private string _repoRoot = "";
    private string _sampleBin = "";
    private readonly List<Process> _hosts = [];

    public HttpClient Vendor { get; } = new() { BaseAddress = new Uri(VendorUrl) };

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
        SmokePorts.EnsureFreeFor("MicrosoftGraph");
        await RunComposeAsync("up", "-d", "wiremock");
        await WaitForVendorAsync();
    }

    public async Task DisposeAsync()
    {
        foreach (var host in _hosts)
        {
            try
            {
                host.Kill(entireProcessTree: true);
                await host.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            host.Dispose();
        }

        Vendor.Dispose();
        await RunComposeAsync("down");
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

    /// <summary>Starts the sample host with the given style environment and config overrides.</summary>
    public RunningHost StartHost(string? environment, Dictionary<string, string>? overrides = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "MicrosoftGraph.dll"));
        if (environment is not null)
        {
            psi.Environment["ASPNETCORE_ENVIRONMENT"] = environment;
        }

        if (overrides is not null)
        {
            foreach (var (key, value) in overrides)
            {
                psi.Environment[key] = value;
            }
        }

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the MicrosoftGraph host");
        _hosts.Add(process);
        return new RunningHost(process);
    }

    /// <summary>The overrides that point the client-secret style at the WireMock stand-ins.</summary>
    public static Dictionary<string, string> StubOverrides() => new()
    {
        ["CredProx__Credentials__graph__TokenEndpoint"] = VendorUrl + TokenPath,
        ["CredProx__Credentials__graph__ClientId"] = "demo-client",
        ["CredProx__Secrets__graph-client-secret"] = "demo-secret",
        ["CredProx__Destinations__graph__Template"] = VendorUrl,
        ["ReverseProxy__Clusters__graph__Destinations__graph__Address"] = VendorUrl + "/",
    };

    public async Task<bool> ExitedWithinAsync(RunningHost host, int seconds)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            await host.Process.WaitForExitAsync(timeout.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>Waits until the host answers HTTP at all (any status) on its configured URL.</summary>
    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the MicrosoftGraph host exited early (code {host.Process.ExitCode}):\n{host.Stderr}");
            }

            try
            {
                using var ok = await probe.GetAsync(HostUrl + "/graph/v1.0/me");
                return;
            }
            catch (HttpRequestException)
            {
                // still warming
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("the MicrosoftGraph host never served its port within 90 s");
    }

    public async Task<int> TokenEndpointCallsAsync()
    {
        using var content = new StringContent(
            JsonSerializer.Serialize(new { method = "POST", urlPath = TokenPath }),
            Encoding.UTF8,
            "application/json");
        using var response = await Vendor.PostAsync("/__admin/requests/count", content);
        response.EnsureSuccessStatusCode();
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("count").GetInt32();
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
        var sampleBin = Path.Combine(repoRoot, "samples", "MicrosoftGraph", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "MicrosoftGraph.dll")))
        {
            throw new InvalidOperationException(
                $"no built MicrosoftGraph host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "MicrosoftGraph");
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

    private async Task WaitForVendorAsync()
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                using var ok = await probe.GetAsync(VendorUrl + "/__admin/mappings");
                if (ok.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // WireMock still starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("WireMock never served its admin API within 90 s");
    }
}
