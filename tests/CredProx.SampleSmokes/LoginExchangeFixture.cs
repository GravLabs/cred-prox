using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the LoginExchange sample: the vendor-neutral WireMock stub from
// the sample's own compose file and the sample host running as a separate `dotnet exec`
// process — exactly how the old smoke script drove it. Each cell resets the stub's
// request journal so the partition checks stay independent of execution order.
[CollectionDefinition("LoginExchange")]
public sealed class LoginExchangeCollection : ICollectionFixture<LoginExchangeFixture>
{
}

public sealed class LoginExchangeFixture : IAsyncLifetime
{
    public const string SampleUrl = "http://localhost:5101";
    public const string StubUrl = "http://localhost:8101";

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
        SmokePorts.EnsureFreeFor("LoginExchange");
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
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "LoginExchange.dll"));
        _sample = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the LoginExchange host");
        _sample.OutputDataReceived += (_, e) => Append(e.Data);
        _sample.ErrorDataReceived += (_, e) => Append(e.Data);
        _sample.BeginOutputReadLine();
        _sample.BeginErrorReadLine();

        // Readiness: a uat request must answer 200 — that proves host, login exchange
        // and stub are all live before any cell starts.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 30; attempt++)
        {
            if (_sample.HasExited)
            {
                break;
            }

            try
            {
                using var request = new HttpRequestMessage(
                    HttpMethod.Get, $"{SampleUrl}/acme/api/v1/timeoff");
                request.Headers.Add("X-API-Env", "uat");
                var response = await probe.SendAsync(request);
                if (response.IsSuccessStatusCode)
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
            $"the LoginExchange path never served 200 within 30 s " +
            $"(exited={_sample.HasExited}, exitCode={(_sample.HasExited ? _sample.ExitCode.ToString() : "n/a")}).\n" +
            $"host output:\n{Tail()}");
    }

    public async Task<(int Status, string Body)> GetTimeoffAsync(string partition)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/acme/api/v1/timeoff");
        request.Headers.Add("X-API-Env", partition);
        using var response = await Sample.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    public async Task ResetJournalAsync()
    {
        using var response = await StubAdmin.DeleteAsync("/__admin/requests");
        Assert.True(response.IsSuccessStatusCode, "resetting the stub journal failed");
    }

    public async Task<string> GetJournalAsync() =>
        await StubAdmin.GetStringAsync("/__admin/requests");

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
        var sampleBin = Path.Combine(repoRoot, "samples", "LoginExchange", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "LoginExchange.dll")))
        {
            throw new InvalidOperationException(
                $"no built LoginExchange host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "LoginExchange");
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
