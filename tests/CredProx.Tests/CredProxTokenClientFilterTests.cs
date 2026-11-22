using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The per-connection token client filter (M5 note N2): <c>credprox-token:&lt;name&gt;</c>
/// clients get the connection's certificate from the <em>live</em> registry at
/// handler-creation time — including a connection added by a reload — while other clients
/// keep their own transport, and an unknown connection fails loudly instead of presenting
/// no certificate. Across the whole credprox-token name space the filter also appends the
/// default User-Agent stamp (product bug 2026-11-22).
/// </summary>
public sealed class CredProxTokenClientFilterTests
{
    private sealed class TestBuilder : HttpMessageHandlerBuilder
    {
        public override string? Name { get; set; }

        public override IList<DelegatingHandler> AdditionalHandlers { get; } = [];

        public override HttpMessageHandler PrimaryHandler { get; set; } = new SocketsHttpHandler();

        public override HttpMessageHandler Build() => PrimaryHandler;
    }

    private static TestBuilder Builder(string clientName, IServiceProvider services)
    {
        var builder = new TestBuilder { Name = clientName };
        // Services has no accessible setter outside the factory; the filter reads it back.
        typeof(HttpMessageHandlerBuilder)
            .GetField("<Services>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(builder, services);
        return builder;
    }

    private static (ConnectionRegistryProvider Provider, ReloadableMemoryConfigurationProvider Reloadable)
        ProviderWithContoso(out IConfigurationRoot config)
    {
        using var cert = TestCertificates.CreateSelfSigned("token-client-contoso");
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(cert),
        });
        config = new ConfigurationBuilder().Add(source).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(secretSource),
                NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);
        return (provider, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static IServiceProvider Services(ConnectionRegistry registry) =>
        new ServiceCollection().AddSingleton(registry).BuildServiceProvider();

    private static (SocketsHttpHandler Handler, SocketsHttpHandler Sentinel) Build(
        IHttpMessageHandlerBuilderFilter filter,
        string clientName,
        IServiceProvider services)
    {
        var builder = Builder(clientName, services);
        var sentinel = new SocketsHttpHandler();
        filter.Configure(b => b.PrimaryHandler = sentinel)(builder);
        return (Assert.IsType<SocketsHttpHandler>(builder.PrimaryHandler), sentinel);
    }

    [Fact]
    public void ConnectionClient_CarriesConnectionCertificate()
    {
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var (handler, _) = Build(filter, "credprox-token:contoso", Services(provider.Current));

        var applied = Assert.IsType<X509Certificate2>(Assert.Single(handler.SslOptions.ClientCertificates!));
        Assert.Equal(provider.Current.Get("contoso").Certificate.Thumbprint, applied.Thumbprint);
    }

    [Fact]
    public void PlainTokenClient_KeepsItsPrimary_AndCarriesUserAgent()
    {
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var builder = Builder(CredProxHttpClientNames.TokenClient, Services(provider.Current));
        var sentinel = new SocketsHttpHandler();
        filter.Configure(b => b.PrimaryHandler = sentinel)(builder);

        // The client's own configuration stands — the filter takes no position on the
        // plain client's transport — but it carries the default User-Agent stamp
        // (product bug 2026-11-22: GitHub 403s a UA-less token exchange at its edge).
        Assert.Same(sentinel, builder.PrimaryHandler);
        Assert.Contains(builder.AdditionalHandlers, static h => h is CredProxUserAgentHandler);
    }

    [Fact]
    public void UnknownConnection_FailsLoudly()
    {
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var ex = Assert.Throws<InvalidOperationException>(
            () => Build(filter, "credprox-token:ghost", Services(provider.Current)));
        Assert.Contains("ghost", ex.Message);
    }

    [Fact]
    public void ConnectionAddedByReload_GetsCertificateWithoutRestart()
    {
        var (provider, reloadable) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        using var beta = TestCertificates.CreateSelfSigned("token-client-beta");
        reloadable.Set("CredProx:Connections:beta:ClientCertificate", "secret:beta-cert");
        reloadable.Set("CredProx:Secrets:beta-cert", TestCertificates.PfxBase64(beta));
        reloadable.Reload();

        // The live registry view (as DI hands it out) already has the new connection.
        var (handler, _) = Build(filter, "credprox-token:beta", Services(provider.Current));
        var applied = Assert.IsType<X509Certificate2>(Assert.Single(handler.SslOptions.ClientCertificates!));
        Assert.Equal(beta.Thumbprint, applied.Thumbprint);
    }

    [Fact]
    public void NoRegistry_FailsWithClearMessage()
    {
        var filter = new CredProxTokenClientFilter();
        var services = new ServiceCollection().BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(
            () => Build(filter, "credprox-token:contoso", services));
        Assert.Contains("AddCredProx", ex.Message);
    }

    [Fact]
    public void ConnectionClient_NeverFollowsRedirects()
    {
        // M45 security finding F-1: a per-connection credential mint must never believe a
        // redirect target's response, so the handler the filter builds carries the refusal
        // itself — not the BCL default of following.
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var (handler, _) = Build(filter, "credprox-token:contoso", Services(provider.Current));
        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public void ConnectionClient_CarriesRedirectGuard()
    {
        // Defense in depth for the same finding: even a primary handler that follows is
        // refused by the guard the filter appends to every credprox-token:<name> client.
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var builder = Builder("credprox-token:contoso", Services(provider.Current));
        filter.Configure(static _ => { })(builder);
        Assert.NotEmpty(builder.AdditionalHandlers);
    }
}
