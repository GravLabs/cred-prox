using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the Operations sample: the WireMock three-personality vendor from
// the sample's own compose file, and the sample host running as a `dotnet exec` process
// on its configured URL. The fixture keeps the vendor-side helpers the old load script
// used — journal count and scenario reset — so each cell drives its own scenario.
[CollectionDefinition("Operations")]
public sealed class OperationsCollection : ICollectionFixture<OperationsFixture>
{
}

public sealed class OperationsFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5091";
    public const string VendorUrl = "http://localhost:8091";

    private string _repoRoot = "";
    private string _sampleBin = "";
    private Process? _host;

    public HttpClient Proxy { get; } = new() { BaseAddress = new Uri(HostUrl) };
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
        SmokePorts.EnsureFreeFor("Operations");
        await RunComposeAsync("up", "-d", "wiremock");
        await WaitForVendorAsync();

        _host = StartHost();

        // Readiness: /health answers Healthy once the credential probes have run.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            if (_host.HasExited)
            {
                break;
            }

            try
            {
                var body = await probe.GetStringAsync(HostUrl + "/health");
                if (body == "Healthy")
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // still warming
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(
            $"the Operations host never reported Healthy within 90 s (hostExited={_host.HasExited}).");
    }

    public async Task<int> GetCodeAsync(string path)
    {
        using var response = await Proxy.GetAsync(path);
        return (int)response.StatusCode;
    }

    public async Task<IReadOnlyList<int>> BurstAsync(string path, int requests)
    {
        var tasks = Enumerable.Range(0, requests)
            .Select(_ => Proxy.GetAsync(path))
            .ToArray();
        var responses = await Task.WhenAll(tasks);
        var codes = responses.Select(r => (int)r.StatusCode).ToList();
        foreach (var response in responses)
        {
            response.Dispose();
        }

        return codes;
    }

    /// <summary>Clears the journal AND restarts the stub scenarios, like the old wm_reset.</summary>
    public async Task ResetVendorAsync()
    {
        using var clear = await Vendor.DeleteAsync("/__admin/requests");
        clear.EnsureSuccessStatusCode();
        using var scenarios = await Vendor.PostAsync("/__admin/scenarios/reset", content: null);
        scenarios.EnsureSuccessStatusCode();
    }

    /// <summary>Requests the vendor has recorded (WireMock 3.x: count is POST-with-body).</summary>
    public async Task<int> VendorRequestCountAsync()
    {
        using var content = new StringContent("{}", Encoding.UTF8, "application/json");
        using var response = await Vendor.PostAsync("/__admin/requests/count", content);
        response.EnsureSuccessStatusCode();
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("count").GetInt32();
    }

    public async Task<string> HealthAsync() => await Proxy.GetStringAsync("/health");

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            try
            {
                _host.Kill(entireProcessTree: true);
                await _host.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            _host.Dispose();
        }

        Proxy.Dispose();
        Vendor.Dispose();
        await RunComposeAsync("down");
    }

    private Process StartHost()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "Operations.dll"));
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the Operations host");
        process.OutputDataReceived += (_, _) => { }; // drain, never block
        process.ErrorDataReceived += (_, _) => { };
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
        var sampleBin = Path.Combine(repoRoot, "samples", "Operations", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "Operations.dll")))
        {
            throw new InvalidOperationException(
                $"no built Operations host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "Operations");
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
