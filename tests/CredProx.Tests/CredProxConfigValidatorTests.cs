using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// The reload-time config validator (M5 note N1): YARP's per-load validation hook refuses
/// unknown <c>CredProx.*</c> references with the startup messages, and a reference added by
/// the same reload validates once the live registries have it.
/// </summary>
public sealed class CredProxConfigValidatorTests
{
    private static (CredProxConfigValidator Validator, ReloadableMemoryConfigurationProvider Reloadable) Build(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        var credentialProvider = services
            .BuildServiceProvider()
            .GetRequiredService<CredentialRegistryProvider>();

        var secretSource = new ConfigurationSecretSource(config);
        var connections = new ConnectionRegistryProvider(
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(secretSource),
                NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);
        var destinations = new DestinationRegistryProvider(
            new DestinationBinder(config, [new HeaderPartitionSourceFactory()]),
            secretSource,
            NullLogger<DestinationRegistryProvider>.Instance);
        var validator = new CredProxConfigValidator(
            credentialProvider, destinations, connections, config);
        return (validator, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static Dictionary<string, string?> Entries()
    {
        using var cert = TestCertificates.CreateSelfSigned("validator-contoso");
        return new Dictionary<string, string?>
        {
            ["CredProx:Credentials:contoso:Type"] = "StaticKey",
            ["CredProx:Credentials:contoso:Secret"] = "secret:contoso-key",
            ["CredProx:Credentials:contoso:Name"] = "X-Contoso",
            ["CredProx:Secrets:contoso-key"] = "value",
            ["CredProx:Destinations:acme:Template"] = "https://acme.example/",
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(cert),
        };
    }

    private static RouteConfig Route(Dictionary<string, string> metadata) => new()
    {
        RouteId = "r",
        ClusterId = "c",
        Match = new RouteMatch { Path = "/{**catch-all}" },
        Metadata = metadata,
    };

    [Fact]
    public async Task Route_UnknownCredential_Rejected()
    {
        var (validator, _) = Build(Entries());

        var errors = await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "ghost" }));

        var error = Assert.Single(errors);
        Assert.Contains("unknown credential 'ghost'", error.Message);
    }

    [Fact]
    public async Task Route_KnownCredential_Accepted()
    {
        var (validator, _) = Build(Entries());

        var errors = await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "contoso" }));

        Assert.Empty(errors);
    }

    [Fact]
    public async Task Route_CredentialWithUnknownConnection_Rejected()
    {
        var entries = Entries();
        entries["CredProx:Credentials:oauth:Type"] = "OAuthClientCredentials";
        entries["CredProx:Credentials:oauth:TokenEndpoint"] = "https://token.example/";
        entries["CredProx:Credentials:oauth:ClientAuthentication"] = "FormPost";
        entries["CredProx:Credentials:oauth:ClientId"] = "id";
        entries["CredProx:Credentials:oauth:ClientSecret"] = "sec";
        entries["CredProx:Credentials:oauth:Connection"] = "ghost-conn";
        var (validator, _) = Build(entries);

        var errors = await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "oauth" }));

        var error = Assert.Single(errors);
        Assert.Contains("unknown connection 'ghost-conn'", error.Message);
    }

    [Fact]
    public async Task Route_UnknownDestination_Rejected()
    {
        var (validator, _) = Build(Entries());

        var errors = await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Destination] = "ghost" }));

        var error = Assert.Single(errors);
        Assert.Contains("unknown destination 'ghost'", error.Message);
    }

    [Fact]
    public async Task Cluster_UnknownConnection_Rejected()
    {
        var (validator, _) = Build(Entries());

        var errors = await validator.ValidateClusterAsync(new ClusterConfig
        {
            ClusterId = "c",
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "ghost" },
        });

        var error = Assert.Single(errors);
        Assert.Contains("unknown connection 'ghost'", error.Message);
    }

    [Fact]
    public async Task Cluster_KnownConnection_Accepted()
    {
        var (validator, _) = Build(Entries());

        var errors = await validator.ValidateClusterAsync(new ClusterConfig
        {
            ClusterId = "c",
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "contoso" },
        });

        Assert.Empty(errors);
    }

    [Fact]
    public async Task Cluster_ConnectionAddedByReload_AcceptedAfterReload()
    {
        var (validator, reloadable) = Build(Entries());
        var cluster = new ClusterConfig
        {
            ClusterId = "c",
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "late" },
        };
        Assert.NotEmpty(await validator.ValidateClusterAsync(cluster));

        using var cert = TestCertificates.CreateSelfSigned("validator-late");
        reloadable.Set("CredProx:Connections:late:ClientCertificate", "secret:late-cert");
        reloadable.Set("CredProx:Secrets:late-cert", TestCertificates.PfxBase64(cert));
        reloadable.Reload();

        Assert.Empty(await validator.ValidateClusterAsync(cluster));
    }
}
