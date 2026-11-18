using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the HmacSigning sample: the host itself — its in-process
// signature-verifying stub vendor is what makes the example verifiable with no Docker.
// The host runs as a separate `dotnet exec` process; the cells drive the proxy routes
// over real sockets. No compose, no stubs to wait for beyond the host itself.
[CollectionDefinition("HmacSigning")]
public sealed class HmacSigningCollection : ICollectionFixture<HmacSigningFixture>
{
}

public sealed class HmacSigningFixture : IAsyncLifetime
{
    public const string SampleUrl = "http://localhost:5098";

    // Set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private readonly StringBuilder _hostOutput = new();
    private readonly object _outputLock = new();
    private Process? _sample;

    public HttpClient Sample { get; } = new() { BaseAddress = new Uri(SampleUrl) };

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
        SmokePorts.EnsureFreeFor("HmacSigning");

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "HmacSigning.dll"));
        _sample = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the HmacSigning host");
        _sample.OutputDataReceived += (_, e) => Append(e.Data);
        _sample.ErrorDataReceived += (_, e) => Append(e.Data);
        _sample.BeginOutputReadLine();
        _sample.BeginErrorReadLine();

        // Readiness: the stub vendor must answer — even its 401 for an unsigned request
        // proves the pipeline is up.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 30; attempt++)
        {
            if (_sample.HasExited)
            {
                break;
            }

            try
            {
                using var response = await probe.PostAsync(
                    $"{SampleUrl}/verify", new StringContent("{}"));
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                    || response.IsSuccessStatusCode)
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
            $"the HmacSigning host never answered within 30 s " +
            $"(exited={_sample.HasExited}, exitCode={(_sample.HasExited ? _sample.ExitCode.ToString() : "n/a")}).\n" +
            $"host output:\n{Tail()}");
    }

    public async Task<(int Status, string Body)> PostSignedAsync(string route, string body)
    {
        using var response = await Sample.PostAsync(route, new StringContent(body));
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
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
        var sampleBin = Path.Combine(repoRoot, "samples", "HmacSigning", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "HmacSigning.dll")))
        {
            throw new InvalidOperationException(
                $"no built HmacSigning host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin);
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
