using System.Diagnostics;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the ADP sample: the docker stack (nginx enforcing mTLS in front of
// a WireMock stub of ADP, plus the loopback Key Vault stub), the generated sample PKI, and
// the sample host started per cell — several cells prove startup-time behavior, so each
// drives its own process on :5086 sequentially. The helpers mirror what the old smoke
// script did: journal access, nginx log access, the KV stub secret install/rotate.
[CollectionDefinition("ADP")]
public sealed class AdpCollection : ICollectionFixture<AdpFixture>
{
}

public sealed class AdpFixture : IAsyncLifetime
{
    public const string HostUrl = "http://localhost:5086";
    public const string StubUrl = "http://localhost:5104";
    public const string KvStubUrl = "http://localhost:8082";
    public const string NginxUrl = "https://localhost:8443";

    private string _repoRoot = "";
    private string _sampleDir = "";
    private string _sampleBin = "";
    private readonly List<Process> _hosts = [];

    public HttpClient Stub { get; } = new() { BaseAddress = new Uri(StubUrl) };
    public HttpClient KvStub { get; } = new() { BaseAddress = new Uri(KvStubUrl) };

    public string SampleDir => _sampleDir;

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
        (_repoRoot, _sampleDir, _sampleBin) = LocatePaths();
        // down first: a leftover stack would trip the free-port check below.
        await RunComposeAsync("down");
        SmokePorts.EnsureFreeFor("ADP");

        await RunScriptAsync("generate-certs.sh");
        await RunComposeAsync("up", "-d");
        await WaitForAdminAsync(StubUrl);
        await WaitForAdminAsync(KvStubUrl);
        await WaitForNginxAsync();
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

        Stub.Dispose();
        KvStub.Dispose();
        await RunComposeAsync("down");
    }

    /// <summary>A sample-host process with drained output; disposing kills it. Not started here.</summary>
    public sealed class RunningHost : IDisposable
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

        public void Dispose()
        {
            try
            {
                if (!Process.HasExited)
                {
                    Process.Kill(entireProcessTree: true);
                    Process.WaitForExit(10_000);
                }
            }
            catch (InvalidOperationException)
            {
                // already gone
            }
        }
    }

    /// <summary>
    /// Starts the sample host. The working directory chooses the content root: the sample
    /// dir has secrets.d (certificates present), the build output dir does not (the
    /// certificateless run). Null environment means the default (offline stack) style.
    /// </summary>
    public RunningHost StartHost(
        string? environment,
        bool certificatesPresent,
        Dictionary<string, string>? overrides = null,
        string[]? clear = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = certificatesPresent ? _sampleDir : _sampleBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_sampleBin, "ADP.dll"));
        // The local stack's TLS material is the sample CA — the same trust step the
        // README tells a human to take (SSL_CERT_FILE=$PWD/certs/ca.crt).
        psi.Environment["SSL_CERT_FILE"] = Path.Combine(_sampleDir, "certs", "ca.crt");
        if (environment is not null)
        {
            psi.Environment["ASPNETCORE_ENVIRONMENT"] = environment;
        }

        foreach (var name in clear ?? [])
        {
            psi.Environment[name] = null; // removes an inherited value
        }

        if (overrides is not null)
        {
            foreach (var (key, value) in overrides)
            {
                psi.Environment[key] = value;
            }
        }

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start the ADP host");
        _hosts.Add(process);
        return new RunningHost(process);
    }

    public string ReadBundle(string name) =>
        File.ReadAllText(Path.Combine(_sampleDir, "secrets.d", name)).Trim();

    /// <summary>
    /// Installs (or replaces) the KV stub's mapping for the certificate secret, mirroring
    /// rotate-kv-stub.sh: bumping attributes.updated is the rotation signal a real vault sends.
    /// </summary>
    public async Task InstallKvSecretAsync(string base64Bundle)
    {
        var updated = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var mapping = $$"""
        {
          "name": "kv-adpClientCert",
          "priority": 5,
          "request": {
            "method": "GET",
            "urlPathPattern": "/secrets/CredProx--Secrets--adpClientCert/?"
          },
          "response": {
            "status": 200,
            "headers": { "Content-Type": "application/json" },
            "jsonBody": {
              "value": {{JsonSerializer.Serialize(base64Bundle)}},
              "id": "https://credprox-adp-sample.vault.azure.net/secrets/CredProx--Secrets--adpClientCert/v-{{updated}}",
              "attributes": { "enabled": true, "updated": {{updated}} }
            }
          }
        }
        """;

        using (var delete = await KvStub.DeleteAsync("/__admin/mappings/name/kv-adpClientCert"))
        {
            // first install has nothing to delete
        }

        using var content = new StringContent(mapping, Encoding.UTF8, "application/json");
        using var install = await KvStub.PostAsync("/__admin/mappings", content);
        install.EnsureSuccessStatusCode();
    }

    public async Task ResetJournalAsync()
    {
        using var clear = await Stub.DeleteAsync("/__admin/requests");
        clear.EnsureSuccessStatusCode();
    }

    public async Task<string> JournalAsync() => await Stub.GetStringAsync("/__admin/requests");

    public async Task<string> NginxLogAsync()
    {
        var psi = new ProcessStartInfo { FileName = "docker", WorkingDirectory = _sampleDir };
        psi.ArgumentList.Add("compose");
        psi.ArgumentList.Add("-p");
        psi.ArgumentList.Add(ComposeProject.NameFor(_repoRoot));
        psi.ArgumentList.Add("logs");
        psi.ArgumentList.Add("nginx");
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not run docker compose logs");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return stdout + stderr;
    }

    /// <summary>The TLS-layer answer nginx gives a request without a client certificate.</summary>
    public async Task<int> NginxCertificatelessCodeAsync()
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        };
        using var client = new HttpClient(handler);
        using var response = await client.GetAsync(NginxUrl + "/api/v1/employees");
        return (int)response.StatusCode;
    }

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

    public async Task WaitForHostAsync(RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (host.Process.HasExited)
            {
                throw new InvalidOperationException(
                    $"the ADP host exited early (code {host.Process.ExitCode}):\n{host.Stdout}\n{host.Stderr}");
            }

            try
            {
                using var ok = await probe.GetAsync(HostUrl + "/adp/api/v1/employees");
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException)
            {
                // still warming
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("the ADP host never served its port within 90 s");
    }

    private (string RepoRoot, string SampleDir, string SampleBin) LocatePaths()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var sampleDir = Path.Combine(repoRoot, "samples", "ADP");
        var sampleBin = Path.Combine(sampleDir, "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "ADP.dll")))
        {
            throw new InvalidOperationException(
                $"no built ADP host at '{sampleBin}' — build the sample first");
        }

        return (repoRoot, sampleDir, sampleBin);
    }

    private async Task RunScriptAsync(string script)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "bash",
            WorkingDirectory = _sampleDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(Path.Combine(_sampleDir, script));
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not run {script}");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"{script} failed (exit {process.ExitCode}): {stderr}{stdout}");
        }
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

    private static async Task WaitForAdminAsync(string baseUrl)
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                using var ok = await probe.GetAsync(baseUrl + "/__admin/mappings");
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

        throw new InvalidOperationException($"WireMock at {baseUrl} never served its admin API within 90 s");
    }

    private static async Task WaitForNginxAsync()
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        };
        using var probe = new HttpClient(handler);
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                // Any HTTP answer (the certificateless refusal itself counts) means the
                // listener is up — container "Started" alone does not.
                using var ok = await probe.GetAsync(NginxUrl + "/api/v1/employees");
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException
                or System.Security.Authentication.AuthenticationException)
            {
                // still warming — a refused or half-torn TLS handshake also means "not yet"
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("nginx never served :8443 within 90 s");
    }
}
