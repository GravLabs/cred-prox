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
    public async Task Route_CredentialNameShadowedByTopLevelSection_StillUnknown()
    {
        // The declared-in-config fallback looks under CredProx:Credentials only: a
        // top-level section that happens to share the credential's name is not the
        // credential — a typo'd CredProx:Credentials block with a decoy section next to
        // it must still be refused, not silently accepted.
        var entries = Entries();
        entries["acme:Decoy"] = "not-a-credential";
        var (validator, _) = Build(entries);

        var errors = await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "acme" }));

        var error = Assert.Single(errors);
        Assert.Contains("unknown credential 'acme'", error.Message);
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

    // --- M31 mutation triage: the stale-registry tolerance (M5 note N1) is a two-sided
    // rule — the live binding wins over a removed config declaration, the config
    // declaration covers a rebind that has not landed — and every side needs its own
    // witness. The witnesses fail the matching registry's rebind (a poison entry) while
    // moving the declaration, so the validator sees registry and config disagree, which
    // is exactly when each side of the ?? and the declaredInConfig checks is load-bearing. ---

    [Fact]
    public async Task NullArguments_Throw()
    {
        var (validator, _) = Build(Entries());

        var routeEx = await Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateRouteAsync(null!).AsTask());
        Assert.Equal("route", routeEx.ParamName);

        var clusterEx = await Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateClusterAsync(null!).AsTask());
        Assert.Equal("cluster", clusterEx.ParamName);
    }

    [Fact]
    public async Task EmptyMetadataValues_OptOut_NoErrors()
    {
        // An empty value is 'no reference here', the same opt-out the startup gate gives.
        var (validator, _) = Build(Entries());

        Assert.Empty(await validator.ValidateRouteAsync(Route(new()
        {
            [CredProxMetadata.Credential] = string.Empty,
            [CredProxMetadata.Destination] = string.Empty,
        })));
        Assert.Empty(await validator.ValidateClusterAsync(new ClusterConfig
        {
            ClusterId = "c",
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = string.Empty },
        }));
    }

    [Fact]
    public async Task CredentialMessage_Pinned()
    {
        var (validator, _) = Build(Entries());

        var error = Assert.Single(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "ghost" })));

        Assert.Equal(
            "Route 'r' references unknown credential 'ghost' in CredProx.Credential.",
            error.Message);
    }

    [Fact]
    public async Task LiveBinding_WinsOverRemovedConfigDeclaration()
    {
        // The credential's binding carries Connection 'ghost'; a reload removes the config
        // key but its poison fails the rebind, so the live registry still says 'ghost'.
        // The binding must keep the reference checked (mutants that keep only the config
        // side, or the config key path, go silent here).
        var entries = OAuthWithConnection("ghost");
        var (validator, reloadable) = Build(entries);

        reloadable.Remove("CredProx:Credentials:oauth:Connection");
        reloadable.Set("CredProx:Credentials:broken:Type", "Magic"); // fails the rebind
        reloadable.Reload();

        var error = Assert.Single(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "oauth" })));

        Assert.Contains("unknown connection 'ghost'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveBindingConnection_WinsOverChangedConfigValue()
    {
        // Both sides name a connection and they disagree (config rewritten, rebind stuck
        // behind the poison): the serving registry's binding is the authority. Checking
        // the config slot first validates a reference the live registry never bound.
        var entries = OAuthWithConnection("contoso");
        var (validator, reloadable) = Build(entries);

        reloadable.Set("CredProx:Credentials:oauth:Connection", "ghost");
        reloadable.Set("CredProx:Credentials:broken:Type", "Magic"); // fails the rebind
        reloadable.Reload();

        Assert.Empty(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "oauth" })));
    }

    [Fact]
    public async Task ConfigDeclaration_CoversARebindThatHasNotLanded_BindingSideNull()
    {
        // Mirror image: the live binding has no Connection, the config just gained one and
        // the rebind is stuck behind the poison. The config fallback is what keeps the
        // fresh reference checked during the race.
        var (validator, reloadable) = Build(Entries());

        reloadable.Set("CredProx:Credentials:contoso:Connection", "late-conn");
        reloadable.Set("CredProx:Credentials:broken:Type", "Magic");
        reloadable.Reload();

        var error = Assert.Single(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "contoso" })));

        Assert.Contains("unknown connection 'late-conn'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveCredentialNoLongerDeclaredInConfig_IsStillKnown()
    {
        // Registry and config fully disagree about a credential (rebind stuck behind the
        // poison, every key removed): the live binding means it is not an unknown
        // credential — reporting one would reject a load the rebind is about to legalize.
        var entries = OAuthWithConnection("ghost");
        var (validator, reloadable) = Build(entries);

        reloadable.Remove("CredProx:Credentials:oauth:Connection");
        reloadable.Remove("CredProx:Credentials:oauth:Type");
        reloadable.Remove("CredProx:Credentials:oauth:TokenEndpoint");
        reloadable.Remove("CredProx:Credentials:oauth:ClientAuthentication");
        reloadable.Remove("CredProx:Credentials:oauth:ClientId");
        reloadable.Remove("CredProx:Credentials:oauth:ClientSecret");
        reloadable.Set("CredProx:Credentials:broken:Type", "Magic");
        reloadable.Reload();

        var error = Assert.Single(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Credential] = "oauth" })));

        Assert.Contains("unknown connection 'ghost'", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("unknown credential", error.Message, StringComparison.Ordinal);
    }

    private static Dictionary<string, string?> OAuthWithConnection(string connection)
    {
        var entries = Entries();
        entries["CredProx:Credentials:oauth:Type"] = "OAuthClientCredentials";
        entries["CredProx:Credentials:oauth:TokenEndpoint"] = "https://token.example/";
        entries["CredProx:Credentials:oauth:ClientAuthentication"] = "FormPost";
        entries["CredProx:Credentials:oauth:ClientId"] = "id";
        entries["CredProx:Credentials:oauth:ClientSecret"] = "sec";
        entries["CredProx:Credentials:oauth:Connection"] = connection;
        return entries;
    }

    [Fact]
    public async Task DestinationDeclaredInConfigWithStaleRegistry_IsAccepted()
    {
        // A reload declaring a new destination while the destination rebind is stuck must
        // pass — the config-declared clause is the race tolerance.
        var (validator, reloadable) = Build(Entries());

        reloadable.Set("CredProx:Destinations:fresh:Template", "https://fresh.example/");
        reloadable.Set("CredProx:Destinations:broken:Bogus", "1"); // unknown key fails the rebind
        reloadable.Reload();

        Assert.Empty(await validator.ValidateRouteAsync(
            Route(new() { [CredProxMetadata.Destination] = "fresh" })));
    }

    [Fact]
    public async Task ConnectionDeclaredInConfigWithStaleRegistry_IsAccepted()
    {
        var (validator, reloadable) = Build(Entries());

        reloadable.Set("CredProx:Connections:fresh:ClientCertificate", "secret:fresh-cert");
        reloadable.Set("CredProx:Connections:broken:ClientCertificate", "secret:missing"); // unresolvable
        reloadable.Reload();

        Assert.Empty(await validator.ValidateClusterAsync(new ClusterConfig
        {
            ClusterId = "c",
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "fresh" },
        }));
    }
}
