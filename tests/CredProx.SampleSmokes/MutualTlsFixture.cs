using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the MutualTls sample: the local test PKI from generate-certs.sh,
// nginx (Docker) requiring a client certificate and echoing its subject, and the sample
// host running as a separate `dotnet exec` process trusting the sample CA via
// SSL_CERT_FILE — exactly how the old smoke script drove it by hand.
[CollectionDefinition("MutualTls")]
public sealed class MutualTlsCollection : ICollectionFixture<MutualTlsFixture>
{
}

public sealed class MutualTlsFixture : IAsyncLifetime
{
    public const string SampleUrl = "http://localhost:5083";
    public const string ClientSubject = "CN=client-alpha";

    // Set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private string _sampleDir = "";
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
        (_repoRoot, _sampleBin, _sampleDir) = LocateSample();
        // down first, fresh PKI, then nginx: the CA must exist before nginx mounts it.
        await RunComposeAsync("down");
        SmokePorts.EnsureFreeFor("MutualTls");
        await RunScriptAsync("./generate-certs.sh", "client-alpha");
        await RunComposeAsync("up", "-d");

        // nginx answers 400 to a TLS connection without a client certificate — that is "up".
        for (var attempt = 0; attempt < 30; attempt++)
        {
            var code = await RunCurlAsync("https://localhost:8444/");
            if (code == "400")
            {
                break;
            }

            await Task.Delay(1000);
        }

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            // The content root is the sample folder: that is where secrets.d/ lives.
            WorkingDirectory = _sampleDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "MutualTls.dll"));
        psi.Environment["SSL_CERT_FILE"] = Path.Combine(_sampleDir, "certs", "ca.crt");
        _sample = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the MutualTls host");
        _sample.OutputDataReceived += (_, e) => Append(e.Data);
        _sample.ErrorDataReceived += (_, e) => Append(e.Data);
        _sample.BeginOutputReadLine();
        _sample.BeginErrorReadLine();

        // Readiness: the mutual-TLS round trip must answer before any cell starts.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 30; attempt++)
        {
            if (_sample.HasExited)
            {
                break;
            }

            try
            {
                var response = await probe.GetAsync($"{SampleUrl}/");
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // still binding its sockets, or nginx not ready yet
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(
            $"the MutualTls host never served 200 within 30 s " +
            $"(exited={_sample.HasExited}, exitCode={(_sample.HasExited ? _sample.ExitCode.ToString() : "n/a")}).\n" +
            $"host output:\n{Tail()}");
    }

    public async Task<(int Status, string Body)> GetRootAsync()
    {
        using var response = await Sample.GetAsync("/");
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
        await RunComposeAsync("down");
    }

    private (string RepoRoot, string SampleBin, string SampleDir) LocateSample()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var sampleDir = Path.Combine(repoRoot, "samples", "MutualTls");
        var sampleBin = Path.Combine(sampleDir, "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "MutualTls.dll")))
        {
            throw new InvalidOperationException(
                $"no built MutualTls host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleBin, sampleDir);
    }

    private async Task RunScriptAsync(string script, string argument)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(_sampleDir, script),
            WorkingDirectory = _sampleDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(argument);
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not run {script}");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{script} {argument} failed (exit {process.ExitCode}): {stderr}{stdout}");
        }
    }

    private async Task<string> RunCurlAsync(string url)
    {
        var psi = new ProcessStartInfo { FileName = "curl" };
        psi.ArgumentList.Add("-sk");
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add("/dev/null");
        psi.ArgumentList.Add("-w");
        psi.ArgumentList.Add("%{http_code}");
        psi.ArgumentList.Add(url);
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("could not run curl");
        var code = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return code.Trim();
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var psi = new ProcessStartInfo { FileName = "docker", WorkingDirectory = _sampleDir };
        psi.ArgumentList.Add("compose");
        psi.ArgumentList.Add("-f");
        psi.ArgumentList.Add(Path.Combine(_sampleDir, "docker-compose.yml"));
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
