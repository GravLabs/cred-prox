using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// The offline world of the PerCallerCredentials sample: real Keycloak from the sample's
// own compose file, and both hosts (the sample proxy and its StubApi vendor stand-in)
// running as separate `dotnet exec` processes with ASPNETCORE_ENVIRONMENT=Development —
// whose config replaces the compose-network hostnames with the exposed ports. The proxy's
// stdout (its audit sink writes there) is captured for the audit cell.
[CollectionDefinition("PerCallerCredentials")]
public sealed class PerCallerCredentialsCollection : ICollectionFixture<PerCallerCredentialsFixture>
{
}

public sealed class PerCallerCredentialsFixture : IAsyncLifetime
{
    public const string KeyA = "9f3a7c2e5b8d1460ae7c4f2b9d8e1a63";
    public const string KeyB = "2c5e8b1f7a3d9604c8b2e5f7a1d39c68";
    public const string KeyReadOnly = "7b1d4e8a2c6f9035d7e1b8a4c2f60d93";
    public const string ProxyUrl = "http://localhost:5100";
    public const string ApiUrl = "http://localhost:5084";
    public const string KeycloakUrl = "http://localhost:5093";

    // Set by InitializeAsync before any cell can see them.
    private string _repoRoot = "";
    private string _sampleBin = "";
    private string _stubBin = "";
    private readonly StringBuilder _hostOutput = new();
    private readonly object _outputLock = new();
    private Process? _api;
    private Process? _proxy;

    public HttpClient Proxy { get; } = new() { BaseAddress = new Uri(ProxyUrl) };

    public string ProxyOutput
    {
        get
        {
            lock (_outputLock)
            {
                return _hostOutput.ToString();
            }
        }
    }

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
        (_repoRoot, _sampleBin, _stubBin) = LocateBins();
        // down first: a leftover stack would trip the free-port check below.
        await RunComposeAsync("down");
        SmokePorts.EnsureFreeFor("PerCallerCredentials");
        await RunComposeAsync("up", "-d", "keycloak");
        await WaitForKeycloakAsync();

        _api = StartHost(_stubBin, "StubApi.dll", ApiUrl, "vendor stub", capture: false);
        _proxy = StartHost(_sampleBin, "PerCallerCredentials.dll", ProxyUrl, "proxy host", capture: true);

        // Readiness: caller app-a must reach its own vendor account before any cell.
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            if (_api.HasExited || _proxy.HasExited)
            {
                break;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, ProxyUrl + "/");
                request.Headers.Add("X-CredProx-Key", KeyA);
                using var response = await probe.SendAsync(request);
                if (await response.Content.ReadAsStringAsync() == "credprox-app-a")
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
            "the PerCallerCredentials path never answered credprox-app-a within 90 s " +
            $"(apiExited={_api.HasExited}, proxyExited={_proxy.HasExited}).\n" +
            $"process output:\n{Tail()}");
    }

    public async Task<(int Status, string Body)> CallAsync(
        string? key, HttpMethod? method = null)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, "/");
        if (key is not null)
        {
            request.Headers.Add("X-CredProx-Key", key);
        }

        using var response = await Proxy.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    public async Task DisposeAsync()
    {
        foreach (var process in new[] { _proxy, _api })
        {
            if (process is null)
            {
                continue;
            }

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

        Proxy.Dispose();
        await RunComposeAsync("down");
    }

    private Process StartHost(string binDir, string dllName, string url, string label, bool capture)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = binDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(binDir, dllName));
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        psi.Environment["ASPNETCORE_URLS"] = url;
        var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start the PerCallerCredentials {label}");
        if (capture)
        {
            process.OutputDataReceived += (_, e) => Append(e.Data);
            process.ErrorDataReceived += (_, e) => Append(e.Data);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private (string RepoRoot, string SampleBin, string StubBin) LocateBins()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var sampleBin = Path.Combine(repoRoot, "samples", "PerCallerCredentials", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(sampleBin, "PerCallerCredentials.dll")))
        {
            throw new InvalidOperationException(
                $"no built PerCallerCredentials host at '{sampleBin}' — build the sample first");
        }

        var stubBin = Path.Combine(repoRoot, "samples", "PerCallerCredentials", "StubApi", "bin", parts[binIndex + 1], "net10.0");
        if (!File.Exists(Path.Combine(stubBin, "StubApi.dll")))
        {
            throw new InvalidOperationException(
                $"no built vendor stub at '{stubBin}' — build the sample first");
        }

        return (repoRoot, sampleBin, stubBin);
    }

    private async Task RunComposeAsync(params string[] args)
    {
        var sampleDir = Path.Combine(_repoRoot, "samples", "PerCallerCredentials");
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

    private async Task WaitForKeycloakAsync()
    {
        using var probe = new HttpClient();
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                using var ok = await probe.GetAsync(
                    $"{KeycloakUrl}/realms/credprox/.well-known/openid-configuration");
                if (ok.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Keycloak still starting
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException("Keycloak never served its realm metadata within 90 s");
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
