using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

[CollectionDefinition("MicrosoftGraph")]
public sealed class MicrosoftGraphCollection : ICollectionFixture<MicrosoftGraphFixture>
{
}

// Starts the shipped MicrosoftGraph sample (prebuilt dll, same bar as the other
// vendors) for the live vendor's single cell. The live run keeps the sample's
// shipped Urls (5085): an interrupted live host cannot shadow anything that
// matters because every leg here goes to real Entra/Graph and the runner owns
// the lifecycle. App-registration material arrives through the scratch dir that
// scripts/live-graph-app.sh pipes it into (client-id.txt, client-secret.txt,
// mode 600) — never through this file's const, never printed.
public sealed class MicrosoftGraphFixture : IDisposable
{
    public const string LiveHostUrl = "http://localhost:5085";
    public const int LiveHostPort = 5085;

    // The scratch contract shared with scripts/live-graph-app.sh:
    public static string ScratchDir =>
        Environment.GetEnvironmentVariable("CREDPROX_M46_SCRATCH") is { Length: > 0 } s ? s : "/tmp/credprox-m46-graph";

    private readonly string _sampleBin = LiveHosts.LocateBin(Path.Combine("samples", "MicrosoftGraph"), "MicrosoftGraph.dll");
    private readonly List<Process> _hosts = [];
    private IReadOnlyCollection<string> _secretValues = [];

    // Reads the run-created client handoff; throws with path names only when the
    // runner did not create it (a wiring bug, never a secret echo).
    public static (string ClientId, string ClientSecret) ReadScratchApp()
    {
        var idPath = Path.Combine(ScratchDir, "client-id.txt");
        var secretPath = Path.Combine(ScratchDir, "client-secret.txt");
        if (!File.Exists(idPath) || !File.Exists(secretPath))
        {
            throw new InvalidOperationException(
                $"the live runner did not create {idPath} / {secretPath} — run scripts/live-graph-app.sh create first");
        }

        var clientId = File.ReadAllText(idPath).Trim();
        var clientSecret = File.ReadAllText(secretPath).Trim();
        if (clientId.Length == 0 || clientSecret.Length == 0)
        {
            throw new InvalidOperationException("the scratch client handoff is empty (zero-length file)");
        }

        return (clientId, clientSecret);
    }

    public LiveHosts.RunningHost StartHost(Dictionary<string, string> env, IReadOnlyCollection<string> secretValues)
    {
        StopHosts();
        LiveHosts.EnsurePortsFree(LiveHostPort);
        _secretValues = secretValues;
        var process = LiveHosts.Start(_sampleBin, "MicrosoftGraph.dll", env);
        _hosts.Add(process);
        return new LiveHosts.RunningHost(process);
    }

    // Any HTTP status counts as ready; the probe path is deliberately not a proxy
    // route, so readiness never forwards a request to Entra or Graph.
    public async Task WaitForHostAsync(LiveHosts.RunningHost host, int seconds = 90)
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
                            $"the MicrosoftGraph host exited early (code {host.Process.ExitCode}):\n" +
                            SecretLeakScanner.Sanitize(host.Stderr, _secretValues));
                    }

                    try
                    {
                        using var _ = await probe.GetAsync(LiveHostUrl + "/live-probe-not-a-route");
                        return true;
                    }
                    catch (HttpRequestException)
                    {
                        return false; // still warming
                    }
                },
                "the MicrosoftGraph host never served its port within 90 s",
                seconds);
        }
        catch (InvalidOperationException)
        {
            // "never ready" is where a config refusal or a wrong bind surfaces —
            // the sanitized host output is the diagnosis, so the failure carries it.
            throw new InvalidOperationException(
                "the MicrosoftGraph host never served its port; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, _secretValues));
        }
    }

    public void Dispose()
    {
        StopHosts();
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
}
