using System.Net;
using CredProx;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The caller-token validation backchannel carries OIDC discovery and the JWKS fetch —
/// whoever's handler rides it decides whose keys authenticate callers (M45 security
/// finding F-1). A host that supplies its own <c>BackchannelHttpHandler</c> (a proxy, a
/// telemetry handler) must keep it running, and it must not reopen the redirect door
/// (M45 security finding R-4): the shipped answer wraps, never replaces. Both
/// registration orders are pinned because plain Configure-callback assignment made the
/// outcome depend on who configured last.
/// </summary>
public sealed class CallerTokenBackchannelTests : IAsyncLifetime
{
    private readonly List<string> _evilHits = [];
    private IHost _idp = null!;
    private IHost _evil = null!;
    private int _idpPort;
    private int _evilPort;

    public Task InitializeAsync()
    {
        _evil = Start(ctx =>
        {
            lock (_evilHits)
            {
                _evilHits.Add($"{ctx.Request.Method} {ctx.Request.Path}");
            }

            return ctx.Response.WriteAsync("evil-keyset");
        });
        _evilPort = ReadPort(_evil);

        _idp = Start(ctx =>
        {
            if (ctx.Request.Path.StartsWithSegments("/metadata"))
            {
                ctx.Response.StatusCode = 302;
                ctx.Response.Headers.Location = $"http://127.0.0.1:{_evilPort}/keys";
                return Task.CompletedTask;
            }

            ctx.Response.StatusCode = 404;
            return Task.CompletedTask;
        });
        _idpPort = ReadPort(_idp);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _evil.StopAsync();
        _evil.Dispose();
        await _idp.StopAsync();
        _idp.Dispose();
    }

    private static IHost Start(RequestDelegate handler)
    {
        return new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(handler));
            })
            .Start();
    }

    private static int ReadPort(IHost host) => new Uri(host.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    private static IConfiguration ValidConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection([
            new KeyValuePair<string, string?>("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            new KeyValuePair<string, string?>("CredProx:CallerToken:Audience", "api://credprox"),
        ]).Build();

    private static JwtBearerOptions BearerOptions(IServiceCollection services) =>
        services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(CallerTokenOptions.Scheme);

    /// <summary>A host-supplied transport that records that it ran — "no throw" does not
    /// prove the host's handler is the one on the wire.</summary>
    private sealed class MarkerHandler : DelegatingHandler
    {
        public int Hits;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Hits);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent("marker-ran"),
            });
        }
    }

    private static void AssertWrappedWith(JwtBearerOptions options, HttpMessageHandler expectedInner)
    {
        var handler = options.BackchannelHttpHandler;
        Assert.NotNull(handler);
        // Three packages ship one internal guard each under the same name; assert by
        // identity of the chain, not by an ambiguous type name.
        Assert.Equal("CredProxRedirectGuard", handler!.GetType().Name);
        Assert.Same(expectedInner, Assert.IsAssignableFrom<DelegatingHandler>(handler).InnerHandler);
    }

    // ---- a host handler is kept and actually runs, in either order ----

    [Fact]
    public async Task HostHandlerConfiguredBefore_IsKeptRunsAndIsGuarded()
    {
        var marker = new MarkerHandler();
        var services = new ServiceCollection();
        services.Configure<JwtBearerOptions>(CallerTokenOptions.Scheme, o => o.BackchannelHttpHandler = marker);
        services.AddCredProxCallerTokenAuthentication(ValidConfig());

        var bearer = BearerOptions(services);
        AssertWrappedWith(bearer, marker);
        using var client = new HttpClient(bearer.BackchannelHttpHandler!);
        Assert.Equal("marker-ran", await client.GetStringAsync("http://127.0.0.1:1/whatever"));
        Assert.Equal(1, marker.Hits);
    }

    [Fact]
    public async Task HostHandlerConfiguredAfter_IsKeptRunsAndIsGuarded()
    {
        var marker = new MarkerHandler();
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        services.Configure<JwtBearerOptions>(CallerTokenOptions.Scheme, o => o.BackchannelHttpHandler = marker);

        var bearer = BearerOptions(services);
        AssertWrappedWith(bearer, marker);
        using var client = new HttpClient(bearer.BackchannelHttpHandler!);
        Assert.Equal("marker-ran", await client.GetStringAsync("http://127.0.0.1:1/whatever"));
        Assert.Equal(1, marker.Hits);
    }

    // ---- a kept host handler must not reopen the redirect door ----

    [Fact]
    public async Task HostHandlerThatFollows_IsRefusedThroughTheWrap()
    {
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        services.Configure<JwtBearerOptions>(CallerTokenOptions.Scheme,
            o => o.BackchannelHttpHandler = new SocketsHttpHandler()); // follows redirects by default

        var bearer = BearerOptions(services);
        Assert.NotNull(bearer.BackchannelHttpHandler);
        Assert.Equal("CredProxRedirectGuard", bearer.BackchannelHttpHandler!.GetType().Name);
        using var client = new HttpClient(bearer.BackchannelHttpHandler);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetStringAsync($"http://127.0.0.1:{_idpPort}/metadata"));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
        // The follow physically happened underneath — the guard speaks after the fact.
        Assert.NotEmpty(_evilHits);
    }

    // ---- host-absent: CredProx's own closed default still lands ----

    [Fact]
    public void NoHostHandler_ShipsRedirectRefusingPrimary()
    {
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());

        var bearer = BearerOptions(services);
        var primary = Assert.IsType<SocketsHttpHandler>(bearer.BackchannelHttpHandler);
        Assert.False(primary.AllowAutoRedirect);
    }

    // ---- the DECIDED handler is the one the handler actually rides ----
    //
    // JwtBearer builds options.Backchannel inside its own post-configure, from the
    // handler property as it stands at that moment. Everything above asserts the
    // property; these two drive options.Backchannel itself — the transport the
    // discovery and JWKS fetches really take — because a post-configure that runs
    // after the framework's sets a property nobody reads again.

    [Fact]
    public async Task HostHandlerThatFollows_IsRefusedThroughTheResolvedBackchannel()
    {
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        services.Configure<JwtBearerOptions>(CallerTokenOptions.Scheme,
            o => o.BackchannelHttpHandler = new SocketsHttpHandler()); // follows redirects by default

        var bearer = BearerOptions(services);
        // The framework has now built Backchannel from whatever property stood then —
        // drive it directly, not a client over the property.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            bearer.Backchannel.GetStringAsync($"http://127.0.0.1:{_idpPort}/metadata"));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NoHostHandler_ResolvedBackchannelDoesNotFollow()
    {
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());

        var bearer = BearerOptions(services);
        using var response = await bearer.Backchannel
            .GetAsync($"http://127.0.0.1:{_idpPort}/metadata");
        // Closed default: the 302 comes back unfollowed — metadata parsing fails on it,
        // and the redirecting authority's key set is never fetched.
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }
}
