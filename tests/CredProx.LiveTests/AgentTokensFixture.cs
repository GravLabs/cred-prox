using System.Diagnostics;
using System.Net;
using System.Text;
using Xunit;

namespace CredProx.LiveTests;

[CollectionDefinition("AgentTokens")]
public sealed class AgentTokensCollection : ICollectionFixture<AgentTokensFixture>
{
}

// Starts the shipped AgentTokens sample (prebuilt dll, same bar as the other
// vendors) plus a loopback stand-in upstream for the live cell. The live run
// overrides Authority/Audience/TokenClientIds (the config the shipped README
// names) and repoints the destination at the stand-in instead of the shipped
// docs.example.com placeholder — a disclosed deviation: the row's proof is the
// real Entra token being validated and MAPPED by CredProx and forwarded; the
// upstream itself is not under test and must not be a live third-party host.
// The stand-in never echoes the Authorization header it receives — only whether
// one arrived — so no minted token can reach any log.
public sealed class AgentTokensFixture : IDisposable
{
    public const string LiveHostUrl = "http://localhost:5096";
    public const int LiveHostPort = 5096;
    public const string StandInUrl = "http://localhost:5098";
    public const int StandInPort = 5098;
    public const string StandInMarker = "agenttokens-standin-ok";

    public static string ScratchDir =>
        Environment.GetEnvironmentVariable("CREDPROX_M46_SCRATCH") is { Length: > 0 } s
            ? s
            : "/tmp/credprox-m46-agenttokens";

    private readonly string _sampleBin = LiveHosts.LocateBin(Path.Combine("samples", "AgentTokens"), "AgentTokens.dll");
    private readonly string _agentBin = LiveHosts.LocateBin(Path.Combine("samples", "AgentTokens", "Agent"), "Agent.dll");
    private readonly List<Process> _hosts = [];
    private IReadOnlyCollection<string> _secretValues = [];
    private HttpListener? _standIn;
    private int _docsRequestCount;
    private int _sawBearerToken;

    public int DocsRequestCount => Volatile.Read(ref _docsRequestCount);
    public bool SawBearerToken => Volatile.Read(ref _sawBearerToken) == 1;

    // Reads the run-created client handoff; throws with path names only when the
    // runner did not create it (a wiring bug, never a secret echo).
    public static (string MappedId, string MappedSecret, string UnmappedId, string UnmappedSecret) ReadScratchApps()
        => ReadScratchApps(ScratchDir);

    // The scaffold contract cell reads a temp scratch it created itself, so the
    // directory is a parameter here; the live cell keeps the zero-arg form.
    public static (string MappedId, string MappedSecret, string UnmappedId, string UnmappedSecret) ReadScratchApps(string dir)
    {
        string Read(string name)
        {
            var path = Path.Combine(dir, name);
            if (!File.Exists(path))
            {
                throw new InvalidOperationException(
                    $"the live runner did not create {path} — run scripts/live-agenttokens-app.sh create first");
            }

            var value = File.ReadAllText(path).Trim();
            if (value.Length == 0)
            {
                throw new InvalidOperationException($"the scratch handoff {name} is empty (zero-length file)");
            }

            return value;
        }

        return (Read("app2-id.txt"), Read("app2-secret.txt"), Read("app3-id.txt"), Read("app3-secret.txt"));
    }

    // The resource app's audience is minted per run (api://<its own appId> —
    // the tenant's default protection policy refuses fixed api:// names), so
    // it is no longer a constant here: the live cell reads it from the same
    // scratch handoff as the client secrets.
    public static string ReadScratchAudience()
        => ReadScratchAudience(ScratchDir);

    public static string ReadScratchAudience(string dir)
    {
        var path = Path.Combine(dir, "resource-audience.txt");
        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"the live runner did not create {path} — run scripts/live-agenttokens-app.sh create first");
        }

        var value = File.ReadAllText(path).Trim();
        // v2 access tokens carry the API's client id as aud, so the audience is that id.
        if (!Guid.TryParse(value, out _))
        {
            throw new InvalidOperationException("the scratch audience handoff is not the API's client id");
        }

        return value;
    }

    public void StartStandIn()
    {
        if (_standIn is not null)
        {
            return;
        }

        LiveHosts.EnsurePortsFree(StandInPort);
        var listener = new HttpListener();
        listener.Prefixes.Add(StandInUrl + "/");
        listener.Start();
        _standIn = listener;
        _ = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await listener.GetContextAsync();
                }
                catch (Exception)
                {
                    return; // listener stopped
                }

                try
                {
                    // The documented upstream path is exactly /docs/readme (every caller:
                    // the offline counter cells, the live cells, the smoke probe) - a prefix
                    // would answer for any /docs-suffixed path too.
                    if (context.Request.HttpMethod == "GET" && context.Request.Url?.AbsolutePath.Equals("/docs/readme", StringComparison.Ordinal) == true)
                    {
                        var auth = context.Request.Headers["Authorization"];
                        Interlocked.Increment(ref _docsRequestCount);
                        if (StandInBearerWitness.IsJwtShaped(auth))
                        {
                            Interlocked.Exchange(ref _sawBearerToken, 1);
                        }

                        // The Authorization value is never written anywhere.
                        var body = Encoding.UTF8.GetBytes($"{{\"marker\":\"{StandInMarker}\"}}");
                        context.Response.ContentType = "application/json";
                        context.Response.StatusCode = 200;
                        await context.Response.OutputStream.WriteAsync(body);
                    }
                    else
                    {
                        context.Response.StatusCode = 404;
                    }
                }
                catch (Exception)
                {
                    // a broken client connection cannot take the stand-in down
                }
                finally
                {
                    try
                    {
                        context.Response.Close();
                    }
                    catch (Exception)
                    {
                        // already closed
                    }
                }
            }
        });
    }

    public LiveHosts.RunningHost StartHost(Dictionary<string, string> env, IReadOnlyCollection<string> secretValues)
    {
        StopHosts();
        LiveHosts.EnsurePortsFree(LiveHostPort);
        _secretValues = secretValues;
        var process = LiveHosts.Start(_sampleBin, "AgentTokens.dll", env);
        _hosts.Add(process);
        return new LiveHosts.RunningHost(process);
    }

    // The shipped agent client as its own process (M53 billable live cell): it mints its
    // OWN Entra token from the AGENT_* env the caller passes — the real end-to-end shape.
    // Unlike the host this is a short run: the cell waits for exit and reads the transcript.
    public LiveHosts.RunningHost StartAgent(Dictionary<string, string> env)
    {
        var process = LiveHosts.Start(_agentBin, "Agent.dll", env);
        _hosts.Add(process);
        return new LiveHosts.RunningHost(process);
    }

    // Any HTTP status counts as ready; the probe path is deliberately not a proxy
    // route, so readiness never forwards a request anywhere.
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
                            $"the AgentTokens host exited early (code {host.Process.ExitCode}):\n" +
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
                "the AgentTokens host never served its port within 90 s",
                seconds);
        }
        catch (InvalidOperationException)
        {
            // "never ready" is where a config refusal surfaces — the sanitized
            // host output is the diagnosis, so the failure carries it.
            throw new InvalidOperationException(
                "the AgentTokens host never served its port; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, _secretValues));
        }
    }

    public void Dispose()
    {
        StopHosts();
        _standIn?.Stop();
        _standIn?.Close();
        _standIn = null;
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
