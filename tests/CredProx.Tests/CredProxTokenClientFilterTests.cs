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
/// are untouched and an unknown connection fails loudly instead of presenting no
/// certificate.
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
    public void PlainTokenClient_LeftUntouched()
    {
        var (provider, _) = ProviderWithContoso(out _);
        var filter = new CredProxTokenClientFilter();

        var (handler, sentinel) = Build(filter, CredProxHttpClientNames.TokenClient, Services(provider.Current));

        // The client's own configuration stands: the filter only owns credprox-token:<name>.
        Assert.Same(sentinel, handler);
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
}
