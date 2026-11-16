using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M39 fold F4 (review verdict): a host that registers the caller-token scheme without
/// caller authentication is a silent fail-open proxy — no caller auth runs and hygiene
/// never marks the request, so the caller's raw JWT is forwarded upstream. The refusal
/// belongs at startup (the two extensions may be registered in any order), and it names
/// both extensions. The 401 detail text follows the token SCHEME being registered —
/// not the mapper — so a host with a mapper but no token scheme keeps advertising keys
/// only.
/// </summary>
public sealed class CallerTokenStartupGuardTests
{
    private static Dictionary<string, string?> TokenOnlyEntries() => new()
    {
        ["CredProx:CallerToken:Authority"] = "https://idp.example",
        ["CredProx:CallerToken:Audience"] = "credprox-api",
        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
    };

    private static readonly RouteConfig PlainRoute = new()
    {
        RouteId = "plain",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/plain/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
        },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://static.example/" },
        },
    };

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    // A registered caller-auth extension with zero callers is itself refused at startup
    // (CredProxStartupValidator); these hosts need one configured caller to reach the
    // 401 detail under test.
    private static void WithOneCaller(Dictionary<string, string?> entries)
    {
        entries["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1";
        entries["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash("caller-key-1");
    }

    private sealed class NullCallerTokenMapper : ICallerTokenMapper
    {
        public CallerTokenMapping? MapToken(ClaimsPrincipal principal) => null;
    }

    private static IHostBuilder ProxyHost(Dictionary<string, string?> entries) =>
        new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([PlainRoute], [AcmeCluster]).AddCredProx(context.Configuration);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            });

    [Fact]
    public async Task TokenExtOnlyHost_RefusesStartup_NamingBothExtensions()
    {
        // The verdict's fail-open probe host: token scheme registered, caller
        // authentication never ran. Today it starts and forwards; it must refuse.
        using var host = ProxyHost(TokenOnlyEntries())
            .ConfigureServices((context, services) =>
                services.AddCredProxCallerTokenAuthentication(context.Configuration))
            .Build();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(default));
        Assert.Contains(nameof(CredProxServiceCollectionExtensions.AddCredProxCallerTokenAuthentication), ex.Message);
        Assert.Contains(nameof(CredProxServiceCollectionExtensions.AddCredProxCallerAuthentication), ex.Message);
        await host.StopAsync();
    }

    [Fact]
    public async Task MapperWithoutTokenScheme_401DetailStaysKeyOnly()
    {
        // A mapper alone must not advertise a token that can never authenticate: the
        // detail keys off the token scheme registration, not the mapper.
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        };
        WithOneCaller(entries);
        using var host = ProxyHost(entries)
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddSingleton<ICallerTokenMapper, NullCallerTokenMapper>();
            })
            .Start();

        var response = await host.GetTestClient().GetAsync("/plain/doc");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("A valid caller API key is required.", body);
        Assert.DoesNotContain("or caller token", body);
    }

    [Fact]
    public async Task TokenSchemeRegistered_Unauthenticated_401DetailAdvertisesBoth()
    {
        var entries = TokenOnlyEntries();
        WithOneCaller(entries);
        using var host = ProxyHost(entries)
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddCredProxCallerTokenAuthentication(context.Configuration);
            })
            .Start();

        var response = await host.GetTestClient().GetAsync("/plain/doc");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("A valid caller API key or caller token is required.", body);
    }

    // M39 fold 2 (architect ruling 00:47Z): startup ADVICE, not refusal. A caller that
    // lists token client ids but names no operation rule can never admit a token — named
    // rules are what a token's roles match — so the guard says so once at startup instead
    // of letting every token request discover it as a bare 403. The caller's key path is
    // untouched, so the host keeps starting.

    private static Dictionary<string, string?> KeysFor(string callerId) => new()
    {
        [$"CredProx:Callers:{callerId}:Keys:0:KeyId"] = "k1",
        [$"CredProx:Callers:{callerId}:Keys:0:KeyHash"] = Hash("caller-key-1"),
    };

    private static (IHost Host, List<string?> Logs) StartLoggedHost(
        Dictionary<string, string?> callerEntries,
        HttpMessageHandler transport,
        Action<AuthenticationBuilder>? registerScheme = null)
    {
        var entries = TokenOnlyEntries();
        foreach (var (key, value) in callerEntries)
        {
            entries[key] = value;
        }

        var logs = new List<string?>();
        var host = ProxyHost(entries)
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddCredProxCallerTokenAuthentication(context.Configuration, registerScheme);
                services.AddSingleton<IForwarderHttpClientFactory>(new StubTransportFactory(transport));
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
            .Start();
        return (host, logs);
    }

    private static int NeverAdmitWarnings(List<string?> logs) =>
        logs.Count(l => l?.Contains("can never admit a token", StringComparison.Ordinal) == true);

    private static async Task<HttpResponseMessage> GetWithKeyAsync(IHost host)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/doc");
        request.Headers.TryAddWithoutValidation("X-CredProx-Key", "caller-key-1");
        return await host.GetTestClient().SendAsync(request);
    }

    private IHost StartEchoUpstream() => new HostBuilder()
        .ConfigureWebHost(web =>
        {
            web.UseTestServer();
            web.Configure(app => app.Run(context => context.Response.WriteAsync("upstream-ok")));
        })
        .Start();

    private sealed class StubTransportFactory(HttpMessageHandler transport) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(transport);
    }

    [Fact]
    public async Task TokenClientIdsWithoutOperations_WarnsOnce_AndStillStarts_KeyPath200()
    {
        // Reviewer label W2: the offender shape is legal config (the binder accepts it),
        // so startup continues — but the operator hears it exactly once, naming the caller.
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-w1");
        entries["CredProx:Callers:agent-w1:TokenClientIds:0"] = "client-sec-w1";
        var (host, logs) = StartLoggedHost(entries, upstream.GetTestServer().CreateHandler());

        Assert.Equal(1, NeverAdmitWarnings(logs));
        Assert.Contains(
            logs,
            l => l?.Contains("agent-w1", StringComparison.Ordinal) == true
                && l?.Contains("can never admit a token", StringComparison.Ordinal) == true);

        var response = await GetWithKeyAsync(host);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task TokenClientIdsWithOnlyUnnamedRule_WarnsOnce_AndStillStarts_KeyPath200()
    {
        // Reviewer label W1: an unnamed rule admits keys but never a token (F3 ruling),
        // which is the same dead end as declaring none — the warning covers both shapes.
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-w2");
        entries["CredProx:Callers:agent-w2:TokenClientIds:0"] = "client-sec-w2";
        entries["CredProx:Callers:agent-w2:Operations:0:Route"] = "plain";
        entries["CredProx:Callers:agent-w2:Operations:0:Methods:0"] = "GET";
        entries["CredProx:Callers:agent-w2:Operations:0:Paths:0"] = "/plain/*";
        var (host, logs) = StartLoggedHost(entries, upstream.GetTestServer().CreateHandler());

        Assert.Equal(1, NeverAdmitWarnings(logs));
        Assert.Contains(
            logs,
            l => l?.Contains("agent-w2", StringComparison.Ordinal) == true
                && l?.Contains("can never admit a token", StringComparison.Ordinal) == true);

        var response = await GetWithKeyAsync(host);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task TokenClientIdsWithNamedRule_NoWarning()
    {
        // Reviewer label W3 (false-warning control): one named rule is a caller tokens CAN admit —
        // silence. Load-bearing for the padded-Name refusal too: a padded Name never
        // reaches the registry, so it refuses at the binder before any warning could fire.
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-w3");
        entries["CredProx:Callers:agent-w3:TokenClientIds:0"] = "client-sec-w3";
        entries["CredProx:Callers:agent-w3:Operations:0:Route"] = "plain";
        entries["CredProx:Callers:agent-w3:Operations:0:Methods:0"] = "GET";
        entries["CredProx:Callers:agent-w3:Operations:0:Paths:0"] = "/plain/*";
        entries["CredProx:Callers:agent-w3:Operations:0:Name"] = "plain-read";
        var (host, logs) = StartLoggedHost(entries, upstream.GetTestServer().CreateHandler());

        Assert.Equal(0, NeverAdmitWarnings(logs));
        await host.StopAsync();
    }

    [Fact]
    public async Task KeyOnlyCaller_NoWarning()
    {
        // Reviewer label W6 (false-warning control): no token client ids means no token expectation —
        // key-path-only callers never hear about rules they never needed.
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-w4");
        var (host, logs) = StartLoggedHost(entries, upstream.GetTestServer().CreateHandler());

        Assert.Equal(0, NeverAdmitWarnings(logs));
        await host.StopAsync();
    }

    // M39 swap-point observability (ADR-0004): a supplied registerScheme callback that
    // registers no handler under the caller-token scheme leaves the scheme absent, so the
    // caller feature refuses every token with no startup clue. One advisory warning names
    // it — and ONLY when the callback was supplied: the guard's scheme-absent path is also
    // the legitimate host-owns-authentication case where the extension never ran, and that
    // host stays silent. The supplied-callback marker is what tells the two apart.

    private static int SwapNoHandlerWarnings(List<string?> logs) =>
        logs.Count(l => l?.Contains("registered no handler under", StringComparison.Ordinal) == true);

    private sealed class StubCallerTokenHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }

    [Fact]
    public async Task RegisterSchemeWithoutHandler_WarnsOnce_AndStillStarts()
    {
        // The callback ran but registered nothing: the swap left no handler under the
        // caller-token scheme. Warn once, keep starting (advice, not refusal).
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-s1");
        var (host, logs) = StartLoggedHost(entries, upstream.GetTestServer().CreateHandler(), _ => { });

        Assert.Equal(1, SwapNoHandlerWarnings(logs));
        Assert.Contains(
            logs,
            l => l?.Contains("registered no handler under CredProxCallerToken", StringComparison.Ordinal) == true
                && l?.Contains("caller-token requests will be refused", StringComparison.Ordinal) == true);
        await host.StopAsync();
    }

    [Fact]
    public async Task RegisterSchemeWithHandlerUnderCallerTokenScheme_NoWarning()
    {
        // False-warning control: a handler under the right name is a working swap — silence.
        using var upstream = StartEchoUpstream();
        var entries = KeysFor("agent-s2");
        var (host, logs) = StartLoggedHost(
            entries,
            upstream.GetTestServer().CreateHandler(),
            builder => builder.AddScheme<AuthenticationSchemeOptions, StubCallerTokenHandler>(
                CredProxAuth.CallerTokenScheme, displayName: null, configureOptions: null));

        Assert.Equal(0, SwapNoHandlerWarnings(logs));
        await host.StopAsync();
    }

    // A stub scheme provider that answers "no such scheme" to everything: a host that
    // owns its scheme set and registers this AFTER the token extension (last registration
    // wins in DI) makes the guard see the caller-token scheme as absent even though the
    // default handler was added.
    private sealed class NoSchemeProvider : IAuthenticationSchemeProvider
    {
        public Task<AuthenticationScheme?> GetDefaultSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetSchemeAsync(string name) => Task.FromResult<AuthenticationScheme?>(null);
        public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() =>
            Task.FromResult<IEnumerable<AuthenticationScheme>>([]);
        public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() =>
            Task.FromResult<IEnumerable<AuthenticationScheme>>([]);
        public Task<bool> HandlerRequestingAuthExistsAsync() => Task.FromResult(false);
        public Task RemoveSchemeAsync(string name) => Task.CompletedTask;
        public Task AddDefaultSchemeAsync(AuthenticationScheme scheme) => Task.CompletedTask;
        public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public void AddScheme(AuthenticationScheme scheme) { }
        public void RemoveScheme(string name) { }
        public Task AddSchemeAsync(AuthenticationScheme scheme) => Task.CompletedTask;
    }

    [Fact]
    public async Task RegisterSchemeNullCallback_SchemeProviderWithoutCallerScheme_NoWarning()
    {
        // The shape the swap cells cannot reach: the extension IS called (with the null
        // callback, so the guard runs and the default handler was added), yet the host's
        // own scheme provider — registered last, winning over the extension's — reports
        // the caller-token scheme as absent. Silence is load-bearing: the warning is
        // marker-driven, NOT scheme-absence-driven, and this host asked for no swap.
        // If the guard's marker check ever widens to scheme absence itself, exactly this
        // cell goes red (no existing cell can see that widening).
        var entries = TokenOnlyEntries();
        WithOneCaller(entries);
        var logs = new List<string?>();
        using var host = ProxyHost(entries)
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddCredProxCallerTokenAuthentication(context.Configuration);
                services.AddSingleton<IAuthenticationSchemeProvider>(new NoSchemeProvider());
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
            .Start();

        Assert.Equal(0, SwapNoHandlerWarnings(logs));
        await host.StopAsync();
    }

    [Fact]
    public async Task CallerTokenExtensionNeverCalled_NoWarning()
    {
        // Host-owns-authentication check: this host never calls the token extension, so
        // the guard is never registered — it cannot fail here. What it proves is narrower
        // than it first reads: the host starts and logs no swap warning. The guard's own
        // silence when the scheme is absent WITHOUT a swap request — the case that can
        // actually go wrong — is pinned by
        // RegisterSchemeNullCallback_SchemeProviderWithoutCallerScheme_NoWarning, which
        // runs the guard for real.
        var entries = TokenOnlyEntries();
        foreach (var (key, value) in KeysFor("agent-s3"))
        {
            entries[key] = value;
        }

        var logs = new List<string?>();
        using var host = ProxyHost(entries)
            .ConfigureServices((context, services) =>
                services.AddCredProxCallerAuthentication(context.Configuration))
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
            .Start();

        Assert.Equal(0, SwapNoHandlerWarnings(logs));
        await host.StopAsync();
    }
}
