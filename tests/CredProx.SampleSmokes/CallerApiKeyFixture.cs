using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the CallerApiKey sample: the upstream WireMock stub from the
// sample's own compose file and the sample host running as a separate `dotnet exec`
// process — exactly how the old smoke script drove it. Cells that inspect the journal
// reset it first so they stay independent of execution order.
[CollectionDefinition("CallerApiKey")]
public sealed class CallerApiKeyCollection : ICollectionFixture<CallerApiKeyFixture>
{
}

public sealed class CallerApiKeyFixture : IAsyncLifetime
{
    public const string SampleUrl = "http://localhost:5087";
    public const string StubUrl = "http://localhost:8100";
    public const string GoodKey = "demo-caller-key-2026";
    public const string WrongKey = "demo-caller-key-WRONG";

    // Set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private readonly StringBuilder _hostOutput = new();
    private readonly object _outputLock = new();
    private Process? _sample;

    public HttpClient Sample { get; } = new() { BaseAddress = new Uri(SampleUrl) };
    public HttpClient StubAdmin { get; } = new() { BaseAddress = new Uri(StubUrl) };

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
        SmokePorts.EnsureFreeFor("CallerApiKey");
        await RunComposeAsync("up", "-d");
        await WaitForStubAsync();

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "CallerApiKey.dll"));
        _sample = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the CallerApiKey host");
        _sample.OutputDataReceived += (_, e) => Append(e.Data);
        _sample.ErrorDataReceived += (_, e) => Append(e.Data);
        _sample.BeginOutputReadLine();
        _sample.BeginErrorReadLine();

        // Readiness: the keyless probe must reach the pipeline and be refused — that
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
                var response = await probe.GetAsync($"{SampleUrl}/api/data");
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
            $"the CallerApiKey host never served the expected 401 within 30 s " +
            $"(exited={_sample.HasExited}, exitCode={(_sample.HasExited ? _sample.ExitCode.ToString() : "n/a")}).\n" +
            $"host output:\n{Tail()}");
    }

    // key == null sends no key header at all.
    public async Task<(int Status, string Body)> GetDataAsync(string? key)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/data");
        if (key is not null)
        {
            request.Headers.Add("X-API-Key", key);
        }

        using var response = await Sample.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    public async Task ResetJournalAsync()
    {
        using var response = await StubAdmin.DeleteAsync("/__admin/requests");
        Assert.True(response.IsSuccessStatusCode, "resetting the stub journal failed");
    }

    // The stub's record of what arrived at /api/data: one header-name list per request.
    public async Task<List<HashSet<string>>> HeadersAtDataAsync()
    {
        using var journal = JsonDocument.Parse(await StubAdmin.GetStringAsync("/__admin/requests"));
        return journal.RootElement.GetProperty("requests").EnumerateArray()
            .Where(r => r.GetProperty("request").GetProperty("url").GetString() == "/api/data")
            .Select(r => r.GetProperty("request").GetProperty("headers")
                .EnumerateObject().Select(h => h.Name).ToHashSet(StringComparer.OrdinalIgnoreCase))
            .ToList();
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

        Sample.Dispose();
        StubAdmin.Dispose();
        await RunComposeAsync("down");
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
        var sampleBin = Path.Combine(repoRoot, "samples", "CallerApiKey", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "CallerApiKey.dll")))
        {
            throw new InvalidOperationException(
                $"no built CallerApiKey host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "CallerApiKey");
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

    private async Task WaitForStubAsync()
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                using var ok = await StubAdmin.GetAsync("/__admin/mappings");
                if (ok.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // container still starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("the WireMock stub never answered within 30 s");
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
