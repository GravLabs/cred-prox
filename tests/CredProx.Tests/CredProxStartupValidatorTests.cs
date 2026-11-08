using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// The startup gate (§3.3 "Validation"): registries bind eagerly, secret declarations are
/// shape-checked, and every YARP <c>CredProx.*</c> metadata reference resolves — all
/// problems arrive in one failure, naming references, never values.
/// </summary>
public sealed class CredProxStartupValidatorTests
{
    private sealed class CollectingLogger : ILogger<CredProxStartupValidator>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }

    /// <summary>A proxy configuration face for the stub provider (YARP exposes no concrete one).</summary>
    private sealed record ProxySpec(
        IReadOnlyList<RouteConfig>? Routes = null,
        IReadOnlyList<ClusterConfig>? Clusters = null);

    private sealed class StubProxyConfigProvider(ProxySpec spec) : IProxyConfigProvider
    {
        public IProxyConfig GetConfig() => new StubProxyConfig(spec);

        private sealed class StubProxyConfig(ProxySpec spec) : IProxyConfig
        {
            public IReadOnlyList<RouteConfig> Routes { get; } = spec.Routes ?? [];
            public IReadOnlyList<ClusterConfig> Clusters { get; } = spec.Clusters ?? [];
            public Microsoft.Extensions.Primitives.IChangeToken ChangeToken { get; } =
                new Microsoft.Extensions.Primitives.CancellationChangeToken(default);

            public void Dispose()
            {
            }
        }
    }

    private readonly CollectingLogger _logger = new();

    private static Dictionary<string, string?> ValidEntries() => new()
    {
        ["CredProx:Credentials:contoso:Type"] = "StaticKey",
        ["CredProx:Credentials:contoso:Secret"] = "secret:contoso-key",
        ["CredProx:Credentials:contoso:Name"] = "X-Contoso",
        ["CredProx:Secrets:contoso-key"] = "value",
        ["CredProx:Destinations:acme:Template"] = "https://{partition}.acme.example/",
        ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
        ["CredProx:Destinations:acme:Allowed:0"] = "prod",
    };

    private static ServiceProvider BuildServices(
        IConfiguration configuration,
        Action<Dictionary<string, string?>>? mutate = null,
        Action<IServiceCollection>? mutateServices = null)
    {
        var entries = ValidEntries();
        mutate?.Invoke(entries);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(entries)
            .Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddSingleton(new DestinationBinder(
            config, [new HeaderPartitionSourceFactory()]).Bind());
        mutateServices?.Invoke(services);
        return services.BuildServiceProvider();
    }

    /// <summary>An OAuth preset in a source, not in configuration — invisible to the secret scan unless referenced.</summary>
    private sealed class AcmeOAuthPresetSource : IPresetSource
    {
        public bool TryGetPreset(string name, out System.Text.Json.JsonElement preset)
        {
            if (name == "acme-oauth")
            {
                preset = System.Text.Json.JsonDocument.Parse("""
                {
                  "Type": "OAuthClientCredentials",
                  "TokenEndpoint": "https://accounts.acme.example/token",
                  "ClientSecret": "secret:acme-client-secret"
                }
                """).RootElement.Clone();
                return true;
            }

            preset = default;
            return false;
        }
    }

    private CredProxStartupValidator Validator(
        IServiceProvider services,
        IConfiguration configuration,
        params ProxySpec[] proxyConfigs) =>
        new(
            services,
            proxyConfigs.Select(c => (IProxyConfigProvider)new StubProxyConfigProvider(c)),
            configuration,
            services.GetRequiredService<SecretReferenceValidator>(),
            services.GetServices<CredProx.Abstractions.IPresetSource>(),
            _logger);

    private static IConfiguration Config(params (string Key, string? Value)[] extra)
    {
        var entries = ValidEntries();
        foreach (var (key, value) in extra)
        {
            entries[key] = value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
    }

    [Fact]
    public async Task ValidConfiguration_Passes()
    {
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r1",
                        Metadata = new Dictionary<string, string>
                        {
                            [CredProxMetadata.Credential] = "contoso",
                            [CredProxMetadata.Destination] = "acme",
                        },
                    },
                ],
                [new ClusterConfig { ClusterId = "c1" }]));

        await validator.StartAsync(default);
    }

    [Fact]
    public async Task RouteWithUnknownCredential_FailsNamingRouteAndReference()
    {
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r1",
                        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "ghost" },
                    },
                ]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("r1", error.Message);
        Assert.Contains("ghost", error.Message);
    }

    [Fact]
    public async Task RouteWithUnknownDestination_Fails()
    {
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r2",
                        Metadata = new Dictionary<string, string> { [CredProxMetadata.Destination] = "ghost" },
                    },
                ]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("r2", error.Message);
        Assert.Contains("ghost", error.Message);
    }

    [Fact]
    public async Task ClusterWithUnknownConnection_Fails()
    {
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(Clusters:
            [
                new ClusterConfig
                {
                    ClusterId = "c9",
                    Metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "ghost" },
                },
            ]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("c9", error.Message);
        Assert.Contains("ghost", error.Message);
    }

    [Fact]
    public async Task CredentialWithUnknownConnection_Fails()
    {
        // Only token-making credential types carry a Connection (StaticKey has none).
        Action<Dictionary<string, string?>> mutate = entries =>
        {
            entries["CredProx:Credentials:contoso:Type"] = "OAuthClientCredentials";
            entries["CredProx:Credentials:contoso:TokenEndpoint"] = "https://token.example/token";
            entries["CredProx:Credentials:contoso:ClientId"] = "cid";
            entries["CredProx:Credentials:contoso:ClientSecret"] = "secret:contoso-key";
            entries["CredProx:Credentials:contoso:Connection"] = "nowhere";
            // Name and Secret are StaticKey keys (OAuth uses ClientSecret and computes
            // Name). M16 rejects the leftovers, so the switch drops them — the connection
            // error below is the point of this test.
            entries.Remove("CredProx:Credentials:contoso:Name");
            entries.Remove("CredProx:Credentials:contoso:Secret");
        };
        var configuration = Config(
            ("CredProx:Credentials:contoso:Type", "OAuthClientCredentials"),
            ("CredProx:Credentials:contoso:TokenEndpoint", "https://token.example/token"),
            ("CredProx:Credentials:contoso:ClientId", "cid"),
            ("CredProx:Credentials:contoso:ClientSecret", "secret:contoso-key"),
            ("CredProx:Credentials:contoso:Connection", "nowhere"));
        using var services = BuildServices(configuration, mutate);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r1",
                        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "contoso" },
                    },
                ]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("nowhere", error.Message);
    }

    [Fact]
    public async Task NestedSecretDeclaration_FailsNamingTheConfigPath()
    {
        var configuration = Config(
            ("CredProx:Credentials:contoso:Secret", "secret:a{secret:b}c"));
        using var services = BuildServices(configuration);
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("nested secret reference", error.Message);
        Assert.Contains("Credentials:contoso:Secret", error.Message);
    }

    [Fact]
    public async Task FullyDynamicSecretDeclaration_LogsWarning()
    {
        var configuration = Config(
            ("CredProx:Credentials:contoso:Secret", "secret:{partition}"));
        using var services = BuildServices(configuration);
        var validator = Validator(services, configuration);

        await validator.StartAsync(default); // a warning, not a failure

        Assert.Contains(_logger.Messages, m => m.Contains("fully-dynamic"));
    }

    [Fact]
    public async Task AllProblems_AreCollectedIntoOneFailure()
    {
        var configuration = Config(("CredProx:Credentials:contoso:Secret", "secret:a{secret:b}c"));
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r-bad",
                        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "ghost" },
                    },
                ]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("r-bad", error.Message);
        Assert.Contains("nested secret reference", error.Message);
    }

    // A host-defined OAuth preset introducing a secret reference — the shape a community
    // preset takes (the library itself ships none since 0.4.0).
    private static readonly (string Key, string? Value)[] AcmeOAuthPreset =
    [
        ("CredProx:Presets:acme-oauth:Type", "OAuthClientCredentials"),
        ("CredProx:Presets:acme-oauth:TokenEndpoint", "https://accounts.acme.example/token"),
        ("CredProx:Presets:acme-oauth:ClientSecret", "secret:acme-client-secret"),
    ];

    [Fact]
    public async Task PresetIntroducedSecret_UnconfiguredAtHost_FailsStartup()
    {
        // §5.2 "Presets" through the hosted gate: the scan runs on the preset-composed
        // view, so a secret reference the preset introduces must resolve through the
        // host's secret source exactly like one the host wrote itself.
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("CredProx:Credentials:music:Preset", "acme-oauth"),
                ("CredProx:Credentials:music:ClientId", "cid")]);
        using var services = BuildServices(configuration);
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));
        Assert.Contains("acme-client-secret", error.Message);
    }

    [Fact]
    public async Task PresetIntroducedSecret_ConfiguredAtHost_Starts()
    {
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("CredProx:Credentials:music:Preset", "acme-oauth"),
                ("CredProx:Credentials:music:ClientId", "cid"),
                ("CredProx:Secrets:acme-client-secret", "value")]);
        // The host's secret source must carry the name the preset introduces — that is
        // the whole point of the rule, so the service's config gets it too.
        using var services = BuildServices(
            configuration,
            e => e["CredProx:Secrets:acme-client-secret"] = "value");
        var validator = Validator(services, configuration);

        await validator.StartAsync(default);
    }

    [Fact]
    public async Task NullPresetReference_OptsOut_SecretlessVariantStarts()
    {
        // The managed-identity overlay shape as behavior: the overlay nulls the base
        // config's Preset, so the secretless variant neither binds the preset's fields
        // nor inherits its secret reference. The preset lives in a source, not in
        // configuration — unreferenced, it stays invisible to the secret scan.
        var baseEntries = ValidEntries();
        baseEntries["CredProx:Credentials:graph:Preset"] = "acme-oauth";
        baseEntries["CredProx:Credentials:graph:ClientId"] = "cid";

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(baseEntries)
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Credentials:graph:Preset"] = null,
                ["CredProx:Credentials:graph:ClientId"] = null,
                ["CredProx:Credentials:graph:Type"] = "TokenCredential",
                ["CredProx:Credentials:graph:Scope"] = "https://graph.microsoft.com/.default",
            })
            .Build();
        using var services = BuildServices(
            configuration,
            mutateServices: s => s.AddSingleton<IPresetSource>(new AcmeOAuthPresetSource()));
        var validator = Validator(services, configuration);

        await validator.StartAsync(default);
    }

    // --- M31 mutation triage: the eager-resolution catches and the caller-route /
    // dynamic-shape edges. Every registry whose bind can throw gets a witness that its
    // failures land in the collected startup report (a swallowed catch would turn a
    // loud startup failure back into a first-request surprise); the caller operation
    // Route cross-check is pinned both ways; and the fully-dynamic warning fires only on
    // shapes with no literal left, never on templates with literal affixes. ---

    [Fact]
    public async Task BrokenCredentialsSection_LandsInStartupReport()
    {
        var configuration = Config();
        using var services = BuildServices(
            configuration,
            mutate: e => e["CredProx:Credentials:broken:Type"] = "Magic");
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("broken", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrokenDestinationsSection_LandsInStartupReport()
    {
        var configuration = Config();
        using var services = BuildServices(
            configuration,
            mutateServices: s => s.AddSingleton<DestinationRegistry>(
                _ => throw new OptionsValidationException("Destinations", typeof(DestinationRegistry), ["simulated destination bind failure"])));
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("simulated destination bind failure", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrokenConnectionsSection_LandsInStartupReport()
    {
        var configuration = Config();
        using var services = BuildServices(
            configuration,
            mutateServices: s => s.AddSingleton<ConnectionRegistry>(
                _ => throw new OptionsValidationException("Connections", typeof(ConnectionRegistry), ["simulated connection bind failure"])));
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("simulated connection bind failure", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrokenCallersSection_LandsInStartupReport()
    {
        // The caller registry is optional, but when it is registered its bind failure is
        // a startup failure — resolved eagerly here precisely for that reason.
        var configuration = Config();
        using var services = BuildServices(
            configuration,
            mutateServices: s => s.AddSingleton<CallerRegistry>(
                _ => throw new OptionsValidationException("Callers", typeof(CallerRegistry), ["caller 'app-a' has no keys"])));
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("caller 'app-a' has no keys", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrokenKillSwitchSection_LandsInStartupReport()
    {
        // M18: an unreadable switch is a startup failure, never an unarmed switch.
        var configuration = Config();
        using var services = BuildServices(
            configuration,
            mutateServices: s => s.AddSingleton<KillSwitchRegistry>(
                _ => throw new OptionsValidationException("KillSwitch", typeof(KillSwitchRegistry), ["simulated kill switch bind failure"])));
        var validator = Validator(services, configuration);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("simulated kill switch bind failure", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerOperation_UnknownRoute_Fails()
    {
        var extras = new (string Key, string? Value)[]
        {
            ("CredProx:Callers:app-a:Keys:0:KeyId", "k1"),
            ("CredProx:Callers:app-a:Keys:0:KeyHash", "sha256:" + new string('a', 64)),
            ("CredProx:Callers:app-a:Operations:0:Route", "ghost-route"),
            ("CredProx:Callers:app-a:Operations:0:Methods:0", "GET"),
        };
        var configuration = Config(extras);
        using var services = BuildServices(
            configuration,
            mutate: e => { foreach (var (key, value) in extras) e[key] = value; },
            mutateServices: s => s.AddCredProxCallerAuthentication(Config(extras)));
        var validator = Validator(
            services,
            configuration,
            new ProxySpec([new RouteConfig { RouteId = "r1" }]));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.StartAsync(default));

        Assert.Contains("caller 'app-a' declares an operation for unknown route 'ghost-route'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerOperation_ExistingRoute_Starts()
    {
        var extras = new (string Key, string? Value)[]
        {
            ("CredProx:Callers:app-a:Keys:0:KeyId", "k1"),
            ("CredProx:Callers:app-a:Keys:0:KeyHash", "sha256:" + new string('a', 64)),
            ("CredProx:Callers:app-a:Operations:0:Route", "r1"),
            ("CredProx:Callers:app-a:Operations:0:Methods:0", "GET"),
        };
        var configuration = Config(extras);
        using var services = BuildServices(
            configuration,
            mutate: e => { foreach (var (key, value) in extras) e[key] = value; },
            mutateServices: s => s.AddCredProxCallerAuthentication(Config(extras)));
        var validator = Validator(
            services,
            configuration,
            new ProxySpec([new RouteConfig { RouteId = "r1" }]));

        await validator.StartAsync(default);
    }

    [Fact]
    public async Task EmptyMetadataValues_AreOptOuts_NotUnknownReferences()
    {
        // An empty CredProx.Credential / CredProx.Destination value opts out of that
        // cross-check; it is not a reference to the empty name.
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(
            services,
            configuration,
            new ProxySpec(
                [
                    new RouteConfig
                    {
                        RouteId = "r1",
                        Metadata = new Dictionary<string, string>
                        {
                            [CredProxMetadata.Credential] = string.Empty,
                            [CredProxMetadata.Destination] = string.Empty,
                        },
                    },
                ]));

        await validator.StartAsync(default);
    }

    [Fact]
    public async Task LiteralSecretDeclaration_NoDynamicWarning()
    {
        var configuration = Config();
        using var services = BuildServices(configuration);
        var validator = Validator(services, configuration);

        await validator.StartAsync(default);

        Assert.DoesNotContain(_logger.Messages, m => m.Contains("fully-dynamic", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("secret:tok-{partition}")]  // literal prefix survives the placeholder strip
    [InlineData("secret:{partition}-suffix")] // literal suffix survives the closing brace
    public async Task TemplateSecretDeclaration_NoDynamicWarning(string declaration)
    {
        // Only shapes with no literal residue admit every name; a template anchored by
        // any literal is bounded and must start silently.
        var configuration = Config(("CredProx:Credentials:contoso:Secret", declaration));
        using var services = BuildServices(
            configuration,
            mutate: e => e["CredProx:Credentials:contoso:Secret"] = declaration);
        var validator = Validator(services, configuration);

        await validator.StartAsync(default);

        Assert.DoesNotContain(_logger.Messages, m => m.Contains("fully-dynamic", StringComparison.Ordinal));
    }
}
