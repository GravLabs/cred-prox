using System.Diagnostics;
using System.Net;
using System.Text;
using Xunit;

namespace CredProx.LiveTests;

[CollectionDefinition("FoundryLocal")]
public sealed class FoundryLocalCollection : ICollectionFixture<FoundryLocalLiveFixture>
{
}

// Starts the shipped FoundryLocalAgent gate (prebuilt dll, same bar as the other
// vendors) plus a loopback stand-in for its TOOL hop only. The model hop is the
// real thing: a resident Foundry Local server on loopback that authenticates
// nothing and costs nothing per call — the row's proof is a REAL Entra caller
// token admitted through the gate to that free local model, so the model is not
// stood in. The tools destination is repointed to the stand-in instead of the
// shipped docs.tools.example placeholder — a disclosed deviation: the upstream is
// not under test and must not be a live third-party host. The stand-in never
// echoes the Authorization header it receives — only whether one arrived — so no
// minted token can reach any log. It also serves the admin arm the gate must
// refuse: reaching a live 200 there would read as a gate failure, so the
// counter's stillness is the witness.
public sealed class FoundryLocalLiveFixture : IDisposable
{
    // The gate runs on its shipped Urls value; the stand-in binds the next free
    // loopback port outside every sample and live-fixture range on this host.
    public const string LiveHostUrl = "http://localhost:5107";
    public const int LiveHostPort = 5107;
    public const string StandInUrl = "http://localhost:5108";
    public const int StandInPort = 5108;
    public const string StandInMarker = "foundrylocal-standin-ok";

    // The foundrylocal runner leg reuses the agenttokens lifecycle script and its
    // scratch handoff unchanged — the same three run-created apps, ids and
    // secrets — so the scratch directory is the same variable with the same
    // default.
    public static string ScratchDir =>
        Environment.GetEnvironmentVariable("CREDPROX_M46_SCRATCH") is { Length: > 0 } s
            ? s
            : "/tmp/credprox-m46-agenttokens";

    public static string ModelBaseUrl => FoundryLocalEnv.ModelBaseUrl;

    private readonly string _sampleBin = LiveHosts.LocateBin(
        Path.Combine("samples", "FoundryLocalAgent"), "FoundryLocalAgent.dll");
    private readonly List<Process> _hosts = [];
    private IReadOnlyCollection<string> _secretValues = [];
    private HttpListener? _standIn;
    private int _docsRequestCount;
    private int _adminRequestCount;
    private int _sawBearerToken;

    public int DocsRequestCount => Volatile.Read(ref _docsRequestCount);
    public int AdminRequestCount => Volatile.Read(ref _adminRequestCount);
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
                    $"the live runner did not create {path} — run scripts/live-run.sh foundrylocal first");
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
    // the tenant's default protection policy refuses fixed api:// names), so it
    // is read from the same scratch handoff as the client secrets, never a
    // constant.
    public static string ReadScratchAudience()
        => ReadScratchAudience(ScratchDir);

    public static string ReadScratchAudience(string dir)
    {
        var path = Path.Combine(dir, "resource-audience.txt");
        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"the live runner did not create {path} — run scripts/live-run.sh foundrylocal first");
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
                    var path = context.Request.Url?.AbsolutePath ?? "";
                    // Exactly the documented docs_lookup path (Agent/Program.cs), like the
                    // admin arm below already is; a prefix answers for /tools/v1/docsXYZ too.
                    if (context.Request.HttpMethod == "GET"
                        && path.Equals("/tools/v1/docs/lookup", StringComparison.Ordinal))
                    {
                        var auth = context.Request.Headers["Authorization"];
                        Interlocked.Increment(ref _docsRequestCount);
                        if (StandInBearerWitness.IsJwtShaped(auth))
                        {
                            Interlocked.Exchange(ref _sawBearerToken, 1);
                        }

                        // The Authorization value is never written anywhere.
                        await WriteMarkerAsync(context);
                    }
                    else if (context.Request.HttpMethod == "GET"
                        && path.Equals("/tools/v1/admin/reset", StringComparison.Ordinal))
                    {
                        // Live and answerable ON PURPOSE: the gate must refuse this
                        // before the request arrives, so the counter is the witness.
                        Interlocked.Increment(ref _adminRequestCount);
                        await WriteMarkerAsync(context);
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

    private static async Task WriteMarkerAsync(HttpListenerContext context)
    {
        var body = Encoding.UTF8.GetBytes($"{{\"marker\":\"{StandInMarker}\"}}");
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = 200;
        await context.Response.OutputStream.WriteAsync(body);
    }

    public LiveHosts.RunningHost StartHost(Dictionary<string, string> env, IReadOnlyCollection<string> secretValues)
    {
        StopHosts();
        LiveHosts.EnsurePortsFree(LiveHostPort);
        _secretValues = secretValues;
        var process = LiveHosts.Start(_sampleBin, "FoundryLocalAgent.dll", env);
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
                            $"the FoundryLocalAgent host exited early (code {host.Process.ExitCode}):\n" +
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
                "the FoundryLocalAgent host never served its port within 90 s",
                seconds);
        }
        catch (InvalidOperationException)
        {
            // "never ready" is where a config refusal surfaces — the sanitized
            // host output is the diagnosis, so the failure carries it.
            throw new InvalidOperationException(
                "the FoundryLocalAgent host never served its port; sanitized host output:\n" +
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
