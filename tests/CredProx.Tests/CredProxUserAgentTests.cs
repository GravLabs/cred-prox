using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Reflection;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Product bug found by the M46 githubapp live run (2026-11-22, shipped in 0.15.0):
/// .NET's HttpClient sends no User-Agent, and GitHub refuses UA-less API requests with
/// a 403 at the administrative edge, so every CredProx-origined token exchange failed
/// against GitHub while every offline cell passed (the stand-ins did not check).
/// Every token client CredProx originates — the plain <c>credprox-token</c> one and each
/// <c>credprox-token:&lt;connection&gt;</c> one — carries a default
/// <c>CredProx/&lt;informational version&gt;</c> User-Agent, and an explicit host default
/// always wins. The forwarded-caller path is a different client and is untouched here.
/// </summary>
public sealed class CredProxUserAgentTests : IAsyncLifetime
{
    private readonly ConcurrentQueue<string> _vendorSawUserAgent = new();
    private readonly IHost _vendor;
    private readonly int _vendorPort;

    public CredProxUserAgentTests()
    {
        // A token endpoint that records the User-Agent Kestrel actually received —
        // the vendor's view, not the request object the client handed to the chain.
        _vendor = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(async ctx =>
                {
                    _vendorSawUserAgent.Enqueue(ctx.Request.Headers.UserAgent.ToString());
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync(
                        """{"access_token":"tok-1","expires_in":3600,"token_type":"Bearer"}""");
                }));
            })
            .Start();
        _vendorPort = new Uri(_vendor.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _vendor.StopAsync();
        _vendor.Dispose();
    }

    private const string TokenJson = "{\"access_token\":\"tok-1\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";

    private static FormUrlEncodedContent TokenForm() =>
        new(new Dictionary<string, string> { ["grant_type"] = "client_credentials" });

    [Fact]
    public async Task PlainTokenClient_TokenCallCarriesUserAgent()
    {
        var server = new StubHttpHandler(HttpStatusCode.OK, TokenJson);
        var services = new ServiceCollection();
        services.AddHttpClient();
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(() => server);
        services.AddSingleton<IHttpMessageHandlerBuilderFilter>(new CredProxTokenClientFilter());
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        using var response = await factory.CreateClient(CredProxHttpClientNames.TokenClient)
            .PostAsync("https://vendor.invalid/token", TokenForm());
        response.EnsureSuccessStatusCode();

        var request = Assert.Single(server.Requests);
        Assert.True(
            request.Headers.TryGetValues("User-Agent", out var values),
            "the token request CredProx originated carried no User-Agent header (the shipped bug)");
        Assert.StartsWith("CredProx/", Assert.Single(values), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectionTokenClient_TokenCallCarriesUserAgent()
    {
        using var cert = TestCertificates.CreateSelfSigned("user-agent-contoso");
        var config = new ConfigurationBuilder().Add(new ReloadableMemoryConfigurationSource(
            new Dictionary<string, string?>
            {
                ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
                ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(cert),
            })).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var registry = new ConnectionRegistryProvider(
            new ConnectionBinder(config, new SecretAccessorFactory(secretSource), NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);

        var services = new ServiceCollection();
        services.AddHttpClient();
        services.AddSingleton<IHttpMessageHandlerBuilderFilter>(new CredProxTokenClientFilter());
        services.AddSingleton(registry.Current);
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        using var client = factory.CreateClient(CredProxHttpClientNames.ConnectionPrefix + "contoso");
        using var response = await client.PostAsync($"http://127.0.0.1:{_vendorPort}/token", TokenForm());
        response.EnsureSuccessStatusCode();

        var seen = Assert.Single(_vendorSawUserAgent.ToArray());
        Assert.True(
            seen.StartsWith("CredProx/", StringComparison.Ordinal),
            $"the vendor saw User-Agent '{seen}' — CredProx's own token call must carry the default");
    }

    [Fact]
    public async Task HostDefaultUserAgent_IsNeverOverridden()
    {
        var server = new StubHttpHandler(HttpStatusCode.OK, TokenJson);
        var services = new ServiceCollection();
        services.AddHttpClient();
        services.AddHttpClient(CredProxHttpClientNames.TokenClient, c => c.DefaultRequestHeaders.UserAgent.ParseAdd("host-agent/9"))
            .ConfigurePrimaryHttpMessageHandler(() => server);
        services.AddSingleton<IHttpMessageHandlerBuilderFilter>(new CredProxTokenClientFilter());
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        using var response = await factory.CreateClient(CredProxHttpClientNames.TokenClient)
            .PostAsync("https://vendor.invalid/token", TokenForm());
        response.EnsureSuccessStatusCode();

        var request = Assert.Single(server.Requests);
        Assert.Equal("host-agent/9", Assert.Single(request.Headers.GetValues("User-Agent")));
    }

    [Fact]
    public async Task Stamp_IsTheInformationalVersionMinusTheSourceRevision()
    {
        var (client, seen) = Chain();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.invalid/token");

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var stamped = Assert.Single(seen.Requests);
        Assert.Equal(CredProxUserAgentHandler.DefaultUserAgent, Assert.Single(stamped.Headers.GetValues("User-Agent")));

        var informational = typeof(CredProxUserAgentHandler).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!
            .InformationalVersion;
        Assert.Equal("CredProx/" + informational.Split('+')[0], CredProxUserAgentHandler.DefaultUserAgent);
        Assert.DoesNotContain("+", CredProxUserAgentHandler.DefaultUserAgent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RawUserAgentOnTheRequest_IsNeverRewritten()
    {
        // A value the caller set directly — even one that fails header parsing — is
        // presence the stamp must respect: the stamp never throws and never rewrites.
        var (client, seen) = Chain();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.invalid/token");
        Assert.True(request.Headers.TryAddWithoutValidation("User-Agent", "weird (raw"));

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var passed = Assert.Single(seen.Requests);
        Assert.Equal("weird (raw", Assert.Single(passed.Headers.GetValues("User-Agent")));
    }

    // ---- the opt-in replacement, for the transport CredProx builds for caller tokens ----

    [Fact]
    public async Task FrameworkBackchannelLabel_IsReplacedWhenOptedIn()
    {
        var seen = new StubHttpHandler(HttpStatusCode.OK, TokenJson) { CaptureBodies = false };
        using var client = new HttpClient(new CredProxUserAgentHandler
        {
            ReplaceFrameworkDefaultUserAgent = true,
            InnerHandler = seen,
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/discovery");
        // The value JwtBearer's own handler merges onto the request before the first
        // delegating handler sees it; the caller-token backchannel cell pins it end to end.
        Assert.True(request.Headers.TryAddWithoutValidation("User-Agent", "Microsoft ASP.NET Core JwtBearer handler"));

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        // The wire User-Agent form is compared joined: the header parser splits the
        // framework label into product tokens, exactly as it does on the wire.
        var stamped = Assert.Single(seen.Requests);
        Assert.Equal(CredProxUserAgentHandler.DefaultUserAgent,
            string.Join(" ", stamped.Headers.GetValues("User-Agent")));
    }

    [Fact]
    public async Task ExplicitUserAgent_WinsOverTheOptInStamp()
    {
        var seen = new StubHttpHandler(HttpStatusCode.OK, TokenJson) { CaptureBodies = false };
        using var client = new HttpClient(new CredProxUserAgentHandler
        {
            ReplaceFrameworkDefaultUserAgent = true,
            InnerHandler = seen,
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/discovery");
        request.Headers.UserAgent.ParseAdd("host-agent/9");

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var passed = Assert.Single(seen.Requests);
        Assert.Equal("host-agent/9", Assert.Single(passed.Headers.GetValues("User-Agent")));
    }

    [Fact]
    public async Task OptInIsOffByDefault_FrameworkLabelPassesThrough()
    {
        var (client, seen) = Chain();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.invalid/token");
        Assert.True(request.Headers.TryAddWithoutValidation("User-Agent", "Microsoft ASP.NET Core JwtBearer handler"));

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var passed = Assert.Single(seen.Requests);
        Assert.Equal("Microsoft ASP.NET Core JwtBearer handler",
            string.Join(" ", passed.Headers.GetValues("User-Agent")));
    }

    private static (HttpClient Client, StubHttpHandler Seen) Chain()
    {
        var seen = new StubHttpHandler(HttpStatusCode.OK, TokenJson) { CaptureBodies = false };
        return (new HttpClient(new CredProxUserAgentHandler { InnerHandler = seen }), seen);
    }
}
