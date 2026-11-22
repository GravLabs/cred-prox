using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// The public caller-authenticator seam in the live pipeline (ADR-0005, M42): an
/// authenticator registered through <c>AddCredProxCallerAuthenticator</c> admits, refuses
/// and carries scopes exactly like the built-ins, registration order decides a request
/// that two authenticators claim, a refusal stops the later ones, the 401 detail composes
/// over the registered hints, and callers declared with no authenticator registered refuse
/// to start.
/// </summary>
public sealed class CallerAuthenticatorSeamTests
{
    private const string StubHeader = "X-Stub-Credential";
    private const string Key = "seam-stub-key";

    /// <summary>Per-slot decisions the two stub authenticators read; registered as one
    /// singleton so each stub type gets its own counter and decide function.</summary>
    private sealed class StubRegistry
    {
        public StubAuthenticatorSettings First { get; } = new();
        public StubAuthenticatorSettings Second { get; } = new();
    }

    private sealed class StubAuthenticatorSettings
    {
        public string Hint { get; set; } = "stub credential";
        public Func<HttpContext, CallerAuthenticationResult>? Decide { get; set; }
        public int Calls;
    }

    private sealed class FirstStubAuthenticator(StubRegistry registry) : ICallerAuthenticator
    {
        public string CredentialRequirementHint => registry.First.Hint;

        public ValueTask<CallerAuthenticationResult> AuthenticateAsync(
            HttpContext context, CancellationToken cancellationToken)
        {
            registry.First.Calls++;
            return ValueTask.FromResult(
                registry.First.Decide?.Invoke(context) ?? CallerAuthenticationResult.NoCredential());
        }
    }

    private sealed class SecondStubAuthenticator(StubRegistry registry) : ICallerAuthenticator
    {
        public string CredentialRequirementHint => registry.Second.Hint;

        public ValueTask<CallerAuthenticationResult> AuthenticateAsync(
            HttpContext context, CancellationToken cancellationToken)
        {
            registry.Second.Calls++;
            return ValueTask.FromResult(
                registry.Second.Decide?.Invoke(context) ?? CallerAuthenticationResult.NoCredential());
        }
    }

    private static CallerAuthenticationResult Admit(
        string callerId,
        IReadOnlySet<string>? scopes = null) =>
        CallerAuthenticationResult.Authenticated(
            new CallerIdentity(callerId, "k-stub"), scopes, StubHeader);

    private static bool HasStubCredential(HttpContext context) =>
        context.Request.Headers.TryGetValue(StubHeader, out var value) && value == "present";

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static Dictionary<string, string?> CallerEntries() => new()
    {
        ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(Key),
        // One named rule covering the plain route: with a scoped credential this is the
        // only thing that can admit, and only when the scope names it (ADR-0004 clause 3).
        ["CredProx:Callers:app-a:Operations:0:Name"] = "plain-read",
        ["CredProx:Callers:app-a:Operations:0:Route"] = "plain",
        ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "GET",
        ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/plain/*",

        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
    };

    // A second route NO caller operation names: the core's allow-list must deny it for
    // every authenticated caller, whichever authenticator admitted that caller.
    private static readonly RouteConfig OtherRoute = new()
    {
        RouteId = "other",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/other/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
        },
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

    private sealed class CapturingHandler(List<HttpRequestMessage> requests) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
        }
    }

    private sealed class StubTransportFactory(HttpMessageHandler transport) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(transport);
    }

    private sealed class SeamHost : IDisposable
    {
        public required IHost Host { get; init; }
        public required StubRegistry Registry { get; init; }
        public required List<HttpRequestMessage> Forwarded { get; init; }

        public void Dispose() => Host.Dispose();
    }

    /// <summary>
    /// Builds the proxy host: the caller-key built-in registers first (when the caller-auth
    /// extension ran), then whatever the test registers through the public authenticator
    /// path — so registration order in these tests is key, first stub, second stub.
    /// </summary>
    private static SeamHost StartHost(
        Action<StubRegistry, IServiceCollection, IConfiguration> registerAuthenticators,
        bool callerAuth = true,
        Dictionary<string, string?>? entries = null)
    {
        entries ??= CallerEntries();
        var registry = new StubRegistry();
        var forwarded = new List<HttpRequestMessage>();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddSingleton(registry);
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                if (callerAuth)
                {
                    services.AddCredProxCallerAuthentication(context.Configuration);
                }

                registerAuthenticators(registry, services, context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([PlainRoute, OtherRoute], [AcmeCluster])
                    .AddCredProx(context.Configuration);
                services.AddSingleton<IForwarderHttpClientFactory>(
                    new StubTransportFactory(new CapturingHandler(forwarded)));
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();

        return new SeamHost { Host = host, Registry = registry, Forwarded = forwarded };
    }

    private static async Task<HttpResponseMessage> GetWithStubCredentialAsync(
        IHost host, string path = "/plain/thing")
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy" + path);
        request.Headers.TryAddWithoutValidation(StubHeader, "present");
        return await host.GetTestClient().SendAsync(request);
    }

    [Fact]
    public async Task ThirdPartyAuthenticator_AdmittedRequest_ReachesUpstream_CredentialHeaderStripped()
    {
        using var host = StartHost((registry, services, config) =>
        {
            registry.First.Decide = context =>
                HasStubCredential(context) ? Admit("app-a") : CallerAuthenticationResult.NoCredential();
            services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
        });

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = Assert.Single(host.Forwarded);
        Assert.Equal("/plain/thing", forwarded.RequestUri!.AbsolutePath);
        // The stub header IS the caller's credential — hygiene strips the presented
        // credential header from the outbound request, whatever its name.
        Assert.False(forwarded.Headers.Contains(StubHeader));
        Assert.Equal(0, host.Registry.Second.Calls);
    }

    [Fact]
    public async Task ScopedThirdPartyResult_EmptyScopes_NamedRuleRefused()
    {
        using var host = StartHost((registry, services, config) =>
        {
            // "A scope set that names nothing": the caller's one named rule locks out.
            registry.First.Decide = context =>
                HasStubCredential(context) ? Admit("app-a", new HashSet<string>()) : CallerAuthenticationResult.NoCredential();
            services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
        });

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(host.Forwarded);
    }

    [Fact]
    public async Task ScopedThirdPartyResult_ScopeNamingTheRule_Admits()
    {
        using var host = StartHost((registry, services, config) =>
        {
            registry.First.Decide = context =>
                HasStubCredential(context)
                    ? Admit("app-a", new HashSet<string> { "plain-read" })
                    : CallerAuthenticationResult.NoCredential();
            services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
        });

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(host.Forwarded);
    }

    [Fact]
    public async Task RefusedCredential_Answers401_StopsLaterAuthenticators_ComposesHintsInBody()
    {
        using var host = StartHost((registry, services, config) =>
        {
            registry.First.Hint = "stub credential";
            registry.First.Decide = context =>
                HasStubCredential(context)
                    ? CallerAuthenticationResult.Refused()
                    : CallerAuthenticationResult.NoCredential();
            registry.Second.Hint = "other stub";
            registry.Second.Decide = context => Admit("app-a");
            services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            services.AddCredProxCallerAuthenticator<SecondStubAuthenticator>(config);
        });

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_unauthenticated", body);
        // The detail composes over every registered hint, in registration order — the
        // stage itself names no credential type.
        Assert.Contains("A valid caller API key or stub credential or other stub is required.", body);
        Assert.Equal(1, host.Registry.First.Calls);
        Assert.Equal(0, host.Registry.Second.Calls); // the refusal won; the next never ran
        Assert.Empty(host.Forwarded);
    }

    [Fact]
    public async Task RegistrationOrderDecides_WhenTwoAuthenticatorsClaimTheSameRequest()
    {
        // No caller-auth extension: the seam registers the core's caller policy itself,
        // so the winner's admit shows as a 200 for the declared caller "app-a".
        using var firstWins = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = _ => Admit("app-a");
                registry.Second.Decide = _ => Admit("app-a");
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
                services.AddCredProxCallerAuthenticator<SecondStubAuthenticator>(config);
            },
            callerAuth: false,
            entries: CallerEntries());

        Assert.Equal(HttpStatusCode.OK, (await GetWithStubCredentialAsync(firstWins.Host)).StatusCode);
        Assert.Equal(1, firstWins.Registry.First.Calls);
        Assert.Equal(0, firstWins.Registry.Second.Calls);

        using var swapped = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = _ => Admit("app-a");
                registry.Second.Decide = _ => Admit("app-a");
                services.AddCredProxCallerAuthenticator<SecondStubAuthenticator>(config);
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            },
            callerAuth: false,
            entries: CallerEntries());

        Assert.Equal(HttpStatusCode.OK, (await GetWithStubCredentialAsync(swapped.Host)).StatusCode);
        Assert.Equal(0, swapped.Registry.First.Calls);
        Assert.Equal(1, swapped.Registry.Second.Calls);
    }

    [Fact]
    public async Task CallersDeclaredWithoutAnyAuthenticator_RefuseStartup()
    {
        // ADR-0005 fail closed: every request would answer 401 with no credential able
        // to admit it — the mirror of the binder's "no caller configured" refusal.
        using var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(CallerEntries()))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([PlainRoute], [AcmeCluster])
                    .AddCredProx(context.Configuration);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Build();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(default));
        Assert.Contains("WithCallerAuthenticator<T>()", ex.Message);
        // R1 (M49): the refusal names the caller left without a way in, not just the section.
        Assert.Contains("app-a", ex.Message);
    }

    [Fact]
    public void CallerWithoutKeysBesideAKeyedSibling_RefusesStartupNamingOnlyIt()
    {
        // R1 per-caller shape: the caller-key machinery is registered (the keyed sibling
        // brought it), so a caller whose only declared way in is caller tokens — with no
        // token machinery on the host — is named on its own, and the sibling is not.
        var entries = CallerEntries();
        entries["CredProx:Callers:app-b:TokenClientIds:0"] = "client-b";
        entries["CredProx:Callers:app-b:Operations:0:Name"] = "plain-read";
        entries["CredProx:Callers:app-b:Operations:0:Route"] = "plain";
        entries["CredProx:Callers:app-b:Operations:0:Methods:0"] = "GET";
        entries["CredProx:Callers:app-b:Operations:0:Paths:0"] = "/plain/*";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartHost((_, _, _) => { }, callerAuth: true, entries: entries));
        Assert.Contains("app-b", ex.Message);
        Assert.DoesNotContain("'app-a'", ex.Message);
    }

    [Fact]
    public void CallerWithoutKeys_ClearsWhenCallerTokenMachineryIsRegistered()
    {
        // The Identity arm of R1: a caller without key hashes is fine once the
        // caller-token machinery is registered — tokens are its way in.
        var entries = CallerEntries();
        entries["CredProx:Callers:app-b:TokenClientIds:0"] = "client-b";
        entries["CredProx:Callers:app-b:Operations:0:Name"] = "plain-read";
        entries["CredProx:Callers:app-b:Operations:0:Route"] = "plain";
        entries["CredProx:Callers:app-b:Operations:0:Methods:0"] = "GET";
        entries["CredProx:Callers:app-b:Operations:0:Paths:0"] = "/plain/*";
        entries["CredProx:CallerToken:Authority"] = "https://login.microsoftonline.com/tenant-id/v2.0";
        entries["CredProx:CallerToken:Audience"] = "api://credprox";

        using var host = StartHost(
            (_, services, config) => services.AddCredProxCallerTokenAuthentication(config),
            callerAuth: true,
            entries: entries);
        Assert.NotNull(host.Host);
    }

    // ---- M49 configuration-driven caller keys: the core entry brings the machinery
    // when a key hash is configured, and registers nothing when none is ----

    private sealed class EntryHost : IDisposable
    {
        public required IHost Host { get; init; }
        public required IServiceProvider Services { get; init; }

        public void Dispose() => Host.Dispose();
    }

    private static EntryHost StartEntryHost(
        Dictionary<string, string?> entries,
        Action<IServiceCollection, IConfiguration>? registerExtra = null)
    {
        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProx(context.Configuration);
                registerExtra?.Invoke(services, context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([PlainRoute], [AcmeCluster])
                    .AddCredProx(context.Configuration);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();

        return new EntryHost { Host = host, Services = host.Services };
    }

    [Fact]
    public async Task ConfiguredKeyHash_RegistersTheCallerKeySchemeThroughTheEntry()
    {
        // No caller-key call anywhere: the key hash in config brings the scheme, the
        // policy and the guard's satisfaction — features work from configuration.
        using var entry = StartEntryHost(CallerEntries());

        var schemes = entry.Services.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var names = (await schemes.GetAllSchemesAsync()).Select(s => s.Name).ToList();
        Assert.Contains(CredProxAuth.CallerKeyScheme, names);

        var policies = entry.Services.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider>();
        Assert.NotNull(await policies.GetPolicyAsync(CredProxAuth.CallerPolicy));
    }

    [Fact]
    public async Task NoKeyHashConfigured_RegistersNoCallerKeySchemeOrPolicy()
    {
        // The QuickStart / GitHubApp shape, now structural: nothing configures a caller
        // key hash, so the core registers no authentication scheme and no policy.
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        };
        using var entry = StartEntryHost(entries);

        // With nothing registered the authentication stack itself may be absent: the
        // provider resolves to null, or carries no caller-key scheme and no policy.
        var schemes = entry.Services.GetService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        List<string> names = [];
        if (schemes is not null)
        {
            names.AddRange((await schemes.GetAllSchemesAsync()).Select(s => s.Name));
        }

        Assert.DoesNotContain(CredProxAuth.CallerKeyScheme, names);

        var policies = entry.Services.GetService<Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider>();
        Assert.True(policies is null || await policies.GetPolicyAsync(CredProxAuth.CallerPolicy) is null);
    }

    [Fact]
    public async Task EntryAutoRegistration_ThenExplicitCall_RegistersTheSchemeOnce()
    {
        // A 0.14-shape host calling AddCredProxCallerAuthentication explicitly must not
        // crash on the entry's own auto-registration — the machinery dedupes by marker.
        using var entry = StartEntryHost(
            CallerEntries(),
            (services, config) => services.AddCredProxCallerAuthentication(config));

        var schemes = entry.Services.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var names = (await schemes.GetAllSchemesAsync())
            .Where(s => s.Name == CredProxAuth.CallerKeyScheme).ToList();
        Assert.Single(names);
    }

    [Fact]
    public async Task ThirdPartyAuthenticatorAlone_SatisfiesTheFailClosedStart()
    {
        // Callers declared, only a third-party authenticator registered: the guard is
        // satisfied — the built-in key path is not required.
        using var host = StartHost((registry, services, config) =>
        {
            registry.First.Decide = _ => CallerAuthenticationResult.NoCredential();
            services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
        }, callerAuth: false);

        var response = await GetWithStubCredentialAsync(host.Host);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task StubOnly_EmptyScopeSet_NamedRulesLockOut_Refused403()
    {
        // The seam alone carries the core's scope narrowing: a scope set that names
        // nothing lets the caller's one named rule lock the request out (ADR-0004 clause 3).
        using var host = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = context =>
                    HasStubCredential(context)
                        ? Admit("app-a", new HashSet<string>())
                        : CallerAuthenticationResult.NoCredential();
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            },
            callerAuth: false);

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(host.Forwarded);
    }

    [Fact]
    public async Task StubOnly_UnknownCallerId_Refused401()
    {
        // An authenticated identity the caller registry does not know is refused exactly
        // as an unknown key holder is: the seam cannot mint callers config never declared.
        using var host = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = context =>
                    HasStubCredential(context)
                        ? Admit("ghost-caller")
                        : CallerAuthenticationResult.NoCredential();
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            },
            callerAuth: false);

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_unauthenticated", body);
        Assert.Empty(host.Forwarded);
    }

    [Fact]
    public async Task StubOnly_Unscoped_RouteOutsideCallerRules_Refused403()
    {
        // No scopes published: only a named operation of THIS caller can admit a route.
        // "other" is named by nobody, so the allow-list denies it.
        using var host = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = context =>
                    HasStubCredential(context) ? Admit("app-a") : CallerAuthenticationResult.NoCredential();
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            },
            callerAuth: false);

        var response = await GetWithStubCredentialAsync(host.Host, "/other/thing");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(host.Forwarded);
    }

    [Fact]
    public async Task StubOnly_Unscoped_OwnRuleMatch_StillAdmitted200()
    {
        // The shape caller keys have always had: no scopes, and one named rule of this
        // caller names the route — admitted. The narrowing locks out, never widens.
        using var host = StartHost(
            (registry, services, config) =>
            {
                registry.First.Decide = context =>
                    HasStubCredential(context) ? Admit("app-a") : CallerAuthenticationResult.NoCredential();
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(config);
            },
            callerAuth: false);

        var response = await GetWithStubCredentialAsync(host.Host);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(host.Forwarded);
    }

    [Fact]
    public async Task AuthenticatorRegisteredWithoutCallers_RefusesStartup()
    {
        // An authenticator registered where no caller is configured could never admit
        // anything: the authenticator registration brings the caller policy, and the
        // startup validator's eager registry bind refuses startup — the binder's "no
        // caller configured" refusal — instead of failing the first request.
        var registry = new StubRegistry();
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        };

        using var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddSingleton(registry);
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthenticator<FirstStubAuthenticator>(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([PlainRoute], [AcmeCluster])
                    .AddCredProx(context.Configuration);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Build();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(default));
        Assert.Contains(
            "no caller is configured",
            string.Join("; ", ex.Failures));
    }

    [Fact]
    public void Authenticated_FactoryRejectsMalformedPresentedHeader()
    {
        // A buggy authenticator fails in its own code — at the factory call — rather
        // than turning the proxy's header hygiene into a request-time 500.
        Assert.Throws<ArgumentException>(
            () => CallerAuthenticationResult.Authenticated(
                new CallerIdentity("app-a", "k-stub"), null, "Bad Header Name"));

        var empty = Assert.Throws<ArgumentException>(
            () => CallerAuthenticationResult.Authenticated(
                new CallerIdentity("app-a", "k-stub"), null, string.Empty));
        Assert.Equal("presentedCredentialHeader", empty.ParamName);

        var ok = CallerAuthenticationResult.Authenticated(
            new CallerIdentity("app-a", "k-stub"), null, StubHeader);
        Assert.Equal(CallerAuthenticationOutcome.Authenticated, ok.Outcome);
    }

    [Fact]
    public async Task NoCallersHostWithoutAuthenticators_StillStarts()
    {
        // The guard's silence half: a configuration that declares no callers needs no
        // authenticator at all (existing no-callers behavior kept).
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        };

        using var host = StartHost(
            (_, _, _) => { },
            callerAuth: false,
            entries: entries);

        await host.Host.StopAsync(); // reaching here without a throw is the assertion
    }
}
