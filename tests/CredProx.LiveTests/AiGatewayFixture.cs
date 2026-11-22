using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CredProx.LiveTests;

[CollectionDefinition("AiGateway")]
public sealed class AiGatewayCollection : ICollectionFixture<AiGatewayFixture>
{
}

// Starts the AiGateway sample host for live and offline runs. The live cell passes
// only the repoint overrides the sample README names for Anthropic-style providers
// plus the machine-local credential env: the shipped appsettings stay in force and
// the sample talks to Anthropic as shipped. The offline cell passes the stand-in
// repoint (the same two keys the shipped Development override uses) with a planted
// sk-ant-shaped fake key — generated per run, never committed or printed. StartHost
// stops any previous host first, so cells never race over a port, and any text a
// failure path may echo goes through the leak scanner first.
public sealed class AiGatewayFixture : IDisposable
{
    // the shipped Urls key is 5088; the live run keeps it, offline uses 5090 so an
    // interrupted offline host can never shadow a later live run's readiness probe
    public const string LiveHostUrl = "http://localhost:5088";
    public const int LiveHostPort = 5088;
    public const string OfflineHostUrl = "http://localhost:5090";
    public const int OfflineHostPort = 5090;
    public const string StubUrl = "http://localhost:8097";

    // Planted fake for the offline legs: the real sk-ant- prefix, so the leak
    // scanner and the value-shape checks bite on exactly the shape the runner
    // greps. It is a test fixture value, not a secret and never sent anywhere.
    public const string StubApiKey = "sk-ant-stubfake-ZZZZZZZZZZZZZZZZZZZZZZ";

    public const string AnthropicAddress = "https://api.anthropic.com/";

    private readonly string _sampleBin = LiveHosts.LocateBin(Path.Combine("samples", "AiGateway"), "AiGateway.dll");
    private readonly string _stubBin = LiveHosts.LocateBin(
        Path.Combine("samples", "AiGateway", "StubApi"), "StubApi.dll");
    private readonly List<Process> _hosts = [];
    private Process? _stub;
    private IReadOnlyCollection<string> _secretValues = [];

    public HttpClient Stub { get; } = new() { BaseAddress = new Uri(StubUrl) };

    // A caller key the test mints itself: the raw value goes to the caller client,
    // only its SHA-256 goes into config — the same shape the sample documents.
    // Caller keys are local test wiring, never the provider secret.
    public static string CallerKeyConfig(string rawKey) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey))).ToLowerInvariant();

    public async Task StartStubAsync()
    {
        LiveHosts.EnsurePortsFree(8097);
        StopStub();
        _stub = LiveHosts.Start(_stubBin, "StubApi.dll", new Dictionary<string, string>
        {
            ["Stub__ProviderKey"] = StubApiKey,
            ["Urls"] = StubUrl,
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
            "the AI-provider stand-in never served its port");
    }

    public LiveHosts.RunningHost StartHost(
        Dictionary<string, string> env,
        IReadOnlyCollection<string> secretValues,
        int hostPort)
    {
        StopHosts();
        LiveHosts.EnsurePortsFree(hostPort);
        _secretValues = secretValues;
        var process = LiveHosts.Start(_sampleBin, "AiGateway.dll", env);
        _hosts.Add(process);
        return new LiveHosts.RunningHost(process);
    }

    // Any HTTP status counts as ready; the probe path is deliberately not a proxy
    // route, so readiness never forwards a request to the vendor.
    public async Task WaitForHostAsync(LiveHosts.RunningHost host, string hostUrl, int seconds = 90)
    {
        using var probe = new HttpClient();
        try
        {
            await LiveHosts.WaitUntilAsync(
                async () =>
                {
                    if (host.Process.HasExited)
                    {
                        throw new InvalidOperationException(
                            $"the AiGateway host exited early (code {host.Process.ExitCode}):\n" +
                            SecretLeakScanner.Sanitize(host.Stderr, _secretValues));
                    }

                    try
                    {
                        using var _ = await probe.GetAsync(hostUrl + "/live-probe-not-a-route");
                        return true;
                    }
                    catch (HttpRequestException)
                    {
                        return false; // still warming
                    }
                },
                "the AiGateway host never served its port within 90 s",
                seconds);
        }
        catch (InvalidOperationException)
        {
            // "never ready" is where a config refusal or a wrong bind surfaces —
            // the sanitized host output is the diagnosis, so the failure carries it.
            throw new InvalidOperationException(
                "the AiGateway host never served its port; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, _secretValues));
        }
    }

    public void Dispose()
    {
        StopHosts();
        StopStub();
        Stub.Dispose();
    }

    private void StopHosts()
    {
        foreach (var host in _hosts)
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

        _hosts.Clear();
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
