using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

namespace CredProx.LiveTests;

[CollectionDefinition("GitHubApp")]
public sealed class GitHubAppCollection : ICollectionFixture<GitHubAppFixture>
{
}

// Starts the GitHubApp sample host for live and witness runs. The live cell passes
// only the machine-local credential env: the shipped appsettings already point at the
// real vendor, so no repoint is set and the sample talks to GitHub as shipped. The
// offline witness cell passes the stand-in repoint (like the offline smokes) with a
// generated RSA pair — generated per run, never committed or printed. StartHost stops
// any previous host first, so cells never race over the sample's port, and any text
// a failure path may echo goes through the leak scanner first.
public sealed class GitHubAppFixture : IDisposable
{
    public const string HostUrl = "http://localhost:5081";
    public const string StubUrl = "http://localhost:8093";
    public const string StubInstallationToken = "ghs_stub_installation";

    private readonly string _sampleBin = LiveHosts.LocateBin(Path.Combine("samples", "GitHubApp"), "GitHubApp.dll");
    private readonly string _stubBin = LiveHosts.LocateBin(
        Path.Combine("samples", "GitHubApp", "StubApi"), "StubApi.dll");
    private readonly List<Process> _liveHosts = [];
    private Process? _stub;
    private IReadOnlyCollection<string> _secretValues = [];

    public HttpClient Stub { get; } = new() { BaseAddress = new Uri(StubUrl) };

    public (string PrivatePem, string PublicPem) GenerateSigningPair()
    {
        using var key = RSA.Create(2048);
        return (key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem());
    }

    public async Task StartStubAsync(string publicPem)
    {
        // Stop this fixture's own stub first, then check the port: a repeat call on this
        // instance is a restart, while a port still bound after the stop is an outside
        // holder the loud diagnostic is meant to name.
        StopStub();
        LiveHosts.EnsurePortsFree(8093);
        _stub = LiveHosts.Start(_stubBin, "StubApi.dll", new Dictionary<string, string>
        {
            ["Stub__SigningKey"] = publicPem,
        });
        await LiveHosts.WaitUntilAsync(
            async () =>
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
            },
            "the GitHub stand-in never served its port");
    }

    public LiveHosts.RunningHost StartHost(
        Dictionary<string, string> env,
        IReadOnlyCollection<string> secretValues)
    {
        StopLiveHosts();
        LiveHosts.EnsurePortsFree(5081);
        _secretValues = secretValues;
        var process = LiveHosts.Start(_sampleBin, "GitHubApp.dll", env);
        _liveHosts.Add(process);
        return new LiveHosts.RunningHost(process);
    }

    // Any HTTP status counts as ready; the probe path is deliberately not a proxy
    // route, so readiness never consumes the token exchange the witness counts.
    public async Task WaitForHostAsync(LiveHosts.RunningHost host, int seconds = 90)
    {
        using var probe = new HttpClient();
        await LiveHosts.WaitUntilAsync(
            async () =>
            {
                if (host.Process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"the GitHubApp host exited early (code {host.Process.ExitCode}):\n" +
                        SecretLeakScanner.Sanitize(host.Stderr, _secretValues));
                }

                try
                {
                    using var _ = await probe.GetAsync(HostUrl + "/readiness-probe");
                    return true;
                }
                catch (HttpRequestException)
                {
                    return false; // still warming
                }
            },
            "the GitHubApp host never served its port within 90 s",
            seconds);
    }

    public void Dispose()
    {
        StopLiveHosts();
        StopStub();
        Stub.Dispose();
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

    private void StopStub()
    {
        if (_stub is null)
        {
            return;
        }

        try
        {
            _stub.Kill(entireProcessTree: true);
            _stub.WaitForExit();
        }
        catch (InvalidOperationException)
        {
            // already gone
        }

        _stub.Dispose();
        _stub = null;
    }
}
