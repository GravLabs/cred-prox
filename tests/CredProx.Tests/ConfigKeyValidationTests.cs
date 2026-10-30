using System.Security.Cryptography.X509Certificates;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M17 (§3.3, §5.2 "Sections unknown keys"): the fail-closed unknown-key rule covers the
/// remaining CredProx sections — <c>CredProx:Destinations</c> and <c>CredProx:Connections</c>
/// (startup AND reload; a rejected rebind keeps the previous registry), the one-shot options
/// sections <c>CredProx:Audit</c>/<c>Health</c>/<c>Throttling</c>/<c>Resilience</c> (eager
/// startup rejection, like their value validators), and the <c>CredProx</c> root itself,
/// where a misspelled section name silently disables a whole feature.
/// </summary>
public sealed class ConfigKeyValidationTests
{
    // ---- CredProx:Destinations ----

    private static DestinationRegistry BindDestinations(params (string Key, string? Value)[] entries) =>
        new DestinationBinder(
                TestConfig.Root(entries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray()),
                [new HeaderPartitionSourceFactory()])
            .Bind();

    [Fact]
    public void UnknownKeyUnderDestination_FailsStartup()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => BindDestinations(
            ("Destinations:vendor:Template", "https://api.vendor.example/"),
            ("Destinations:vendor:Templat", "https://typo.vendor.example/")));

        Assert.Contains("destination 'vendor'", ex.Message);
        Assert.Contains("'Templat'", ex.Message);
        Assert.Contains("CredProx:Destinations:vendor", ex.Message);
        Assert.Contains("Allowed, Partition, StripHeader, Template", ex.Message);
    }

    [Fact]
    public void NestedBlockUnderDestinationScalar_FailsStartup()
    {
        // Partition is a single value on the definition — a block under it binds to nothing.
        var ex = Assert.Throws<OptionsValidationException>(() => BindDestinations(
            ("Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("Destinations:acme:Partition:From", "header:X-Env")));

        Assert.Contains("destination 'acme'", ex.Message);
        Assert.Contains("nested block under 'Partition'", ex.Message);
    }

    [Fact]
    public void NonIndexKeyInsideDestinationList_FailsStartup()
    {
        // M18 walker rule: list entries must be indexed — Allowed:oops is read by nobody,
        // and the M17 leaf rule left it through because a list's children are its elements.
        var ex = Assert.Throws<OptionsValidationException>(() => BindDestinations(
            ("Destinations:acme:Template", "https://acme.example/"),
            ("Destinations:acme:Allowed:oops", "prod")));

        Assert.Contains("'Allowed:oops'", ex.Message);
        Assert.Contains("must be indexed", ex.Message);
    }

    [Fact]
    public void ValidRichDestinationConfig_BindsEveryKey()
    {
        var registry = BindDestinations(
            ("Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("Destinations:acme:Partition", "header:X-Env"),
            ("Destinations:acme:Allowed:0", "prod"),
            ("Destinations:acme:Allowed:1", "staging"),
            ("Destinations:acme:StripHeader", "true"));

        var entry = registry.Get("acme");
        Assert.NotNull(entry);
        Assert.Equal("https://prod.acme.example/", entry.ResolvePrefix("prod"));
    }

    [Fact]
    public void DestinationKeys_AreCaseInsensitive()
    {
        var registry = BindDestinations(
            ("destinations:vEndor:tEMPLATE", "https://api.vendor.example/"),
            ("destinations:vEndor:stripheader", "false"));

        Assert.NotNull(registry.Get("vendor"));
    }

    [Fact]
    public void UnknownKeyReload_DestinationsKeepThePreviousRegistry()
    {
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:Destinations:vendor:Template"] = "https://api.vendor.example/",
        });
        var config = new ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var secrets = new ConfigurationSecretSource(config);
        var provider = new DestinationRegistryProvider(
            new DestinationBinder(config, [new HeaderPartitionSourceFactory()]),
            secrets,
            NullLogger<DestinationRegistryProvider>.Instance);
        var before = provider.Current;

        reloadable.Set("CredProx:Destinations:vendor:Extra", "x");
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.NotNull(provider.Current.Get("vendor"));
    }

    // ---- CredProx:Connections ----

    private readonly X509Certificate2 _cert = TestCertificates.CreateSelfSigned("m17-conn");

    // The two real keys plus their secrets; the certificate loads eagerly, so the initial
    // bind succeeds and the tests isolate the unknown-key behavior.
    private Dictionary<string, string?> PfxConnection() => new()
    {
        ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
        ["CredProx:Connections:contoso:ClientCertificatePassword"] = "p@ss",
        ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(_cert, "p@ss"),
    };

    private static ConnectionRegistry BindConnections(IConfiguration config) =>
        new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance)
            .Bind();

    [Fact]
    public void UnknownKeyUnderConnection_FailsStartup()
    {
        var entries = PfxConnection();
        entries["CredProx:Connections:contoso:ClientCertificat"] = "secret:typo";
        var config = Root(entries);

        var ex = Assert.Throws<OptionsValidationException>(() => BindConnections(config));

        Assert.Contains("connection 'contoso'", ex.Message);
        Assert.Contains("'ClientCertificat'", ex.Message);
        Assert.Contains("ClientCertificate, ClientCertificatePassword", ex.Message);
    }

    [Fact]
    public void NestedBlockUnderClientCertificate_FailsStartup()
    {
        // The certificate keys are single values — a block under one binds to nothing.
        var entries = PfxConnection();
        entries["CredProx:Connections:contoso:ClientCertificate:Blob"] = "secret:nested";
        var config = Root(entries);

        var ex = Assert.Throws<OptionsValidationException>(() => BindConnections(config));

        Assert.Contains("nested block under 'ClientCertificate'", ex.Message);
    }

    [Fact]
    public void UnknownKeyReload_ConnectionsKeepThePreviousRegistry()
    {
        var source = new ReloadableMemoryConfigurationSource(PfxConnection());
        var config = new ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var secrets = new ConfigurationSecretSource(config);
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(config, new SecretAccessorFactory(secrets), NullLoggerFactory.Instance),
            secrets,
            NullLogger<ConnectionRegistryProvider>.Instance);
        var before = provider.Current;

        // The certificate references stay unchanged — only the reload-introduced typo
        // distinguishes this rebind from the initial bind.
        reloadable.Set("CredProx:Connections:contoso:Thumbprint", "aa-bb");
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.NotNull(before);
    }

    // ---- one-shot options sections (eager startup rejection) ----

    [Fact]
    public void UnknownKeyUnderAudit_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?> { ["CredProx:Audit:SinkTimout"] = "00:00:05" });

        var ex = Assert.Throws<OptionsValidationException>(() => services.AddCredProxAudit(config));

        Assert.Contains("'CredProx:Audit' section", ex.Message);
        Assert.Contains("'SinkTimout'", ex.Message);
        Assert.Contains("SinkTimeout", ex.Message);
    }

    [Fact]
    public void UnknownKeyUnderHealth_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?> { ["CredProx:Health:ProbeIntervall"] = "00:01:00" });

        var ex = Assert.Throws<OptionsValidationException>(() => services.AddCredProxHealthProbes(config));

        Assert.Contains("'CredProx:Health' section", ex.Message);
        Assert.Contains("'ProbeIntervall'", ex.Message);
    }

    [Fact]
    public void UnknownKeyUnderThrottling_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Throttling:PermitsPerInterval"] = "100",
            ["CredProx:Throttling:Defaul"] = "5",
        });

        var ex = Assert.Throws<OptionsValidationException>(() => services.AddCredProxThrottling(config));

        Assert.Contains("'CredProx:Throttling' section", ex.Message);
        Assert.Contains("'Defaul'", ex.Message);
    }

    [Fact]
    public void UnknownKeyUnderResilience_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?> { ["CredProx:Resilience:MaxRetrie"] = "3" });

        var ex = Assert.Throws<OptionsValidationException>(() => services.AddCredProxResilience(config));

        Assert.Contains("'CredProx:Resilience' section", ex.Message);
        Assert.Contains("'MaxRetrie'", ex.Message);
    }

    [Fact]
    public void UnknownKeyInsideThrottlingCluster_FailsStartup()
    {
        // Cluster names stay user-defined, but each entry is bound into the typed cluster
        // options — a field typo inside one must not bind to nothing either.
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Throttling:Clusters:vendor:PermitsPerIntervall"] = "10",
        });

        var ex = Assert.Throws<OptionsValidationException>(() => services.AddCredProxThrottling(config));

        Assert.Contains("'Clusters:vendor:PermitsPerIntervall'", ex.Message);
        Assert.Contains("MaxConcurrency", ex.Message);
    }

    [Fact]
    public void ValidOptionsSections_AcceptTheirWholeSurface()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Audit:Enabled"] = "true",
            ["CredProx:Audit:SinkTimeout"] = "00:00:05",
            ["CredProx:Audit:IncludeHeaders:0"] = "X-Trace-Id",
            ["CredProx:Health:ProbeInterval"] = "00:01:00",
            ["CredProx:Health:CertWarningDays"] = "30",
            ["CredProx:Throttling:PermitsPerInterval"] = "100",
            ["CredProx:Throttling:Clusters:vendor:MaxConcurrency"] = "4",
            ["CredProx:Resilience:MaxRetries"] = "4",
            ["CredProx:Resilience:Clusters:vendor:AttemptTimeout"] = "00:00:10",
        });

        services.AddCredProxAudit(config);
        services.AddCredProxThrottling(config);
        services.AddCredProxResilience(config);
        // Health registers hosted services and health checks — still collection-only.
        services.AddCredProxHealthProbes(config);

        Assert.NotNull(services);
    }

    // ---- the CredProx root ----

    [Fact]
    public void MisspelledSectionName_FailsStartup()
    {
        // The whole-feature typo: a wrong section name configures nothing and used to be
        // silent — throttling would simply be off.
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Throteling:PermitsPerInterval"] = "100",
        });

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddReverseProxy().AddCredProx(config));

        Assert.Contains("'CredProx' section", ex.Message);
        Assert.Contains("'Throteling'", ex.Message);
        Assert.Contains("Throttling", ex.Message);
    }

    [Fact]
    public void UnknownKeyAtRoot_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?> { ["CredProx:InboundKeyHeader"] = "X-Key" });
        services.AddReverseProxy().AddCredProx(config); // the one real core option binds fine

        config = Root(new Dictionary<string, string?> { ["CredProx:InboundKeyHeaderr"] = "X-Key" });
        var services2 = new ServiceCollection();
        var ex = Assert.Throws<OptionsValidationException>(
            () => services2.AddReverseProxy().AddCredProx(config));
        Assert.Contains("'InboundKeyHeaderr'", ex.Message);
    }

    /// <summary>
    /// M20 review F3: the <c>Scrubbing</c> section joined the fail-closed topology, and a
    /// typo in its only key (<c>Enabled</c>) must refuse startup — silently dropping it
    /// would leave scrubbing on (or off) the opposite of what the config says.
    /// </summary>
    [Fact]
    public void UnknownKeyUnderScrubbing_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Scrubbing:Enabbled"] = "false",
        });

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddReverseProxy().AddCredProx(config));

        Assert.Contains("'CredProx:Scrubbing' section", ex.Message);
        Assert.Contains("'Enabbled'", ex.Message);
        Assert.Contains("Enabled", ex.Message);
    }

    /// <summary>
    /// M24: the <c>Errors</c> section joined the fail-closed topology — a typo'd key
    /// would silently leave vendor normalisation on (or the cap at its default).
    /// </summary>
    [Fact]
    public void UnknownKeyUnderErrors_FailsStartup()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Errors:Enabledd"] = "false",
        });

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddReverseProxy().AddCredProx(config));

        Assert.Contains("'CredProx:Errors' section", ex.Message);
        Assert.Contains("'Enabledd'", ex.Message);
        Assert.Contains("Enabled", ex.Message);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    public void NonPositiveErrorCap_FailsStartup(string cap)
    {
        // A cap at or below zero would mean "normalise nothing" by a confusing route;
        // refusing startup beats a silent always-overflow posture.
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:Errors:MaxNormalisedBodyBytes"] = cap,
        });

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddReverseProxy().AddCredProx(config));

        Assert.Contains("MaxNormalisedBodyBytes must be greater than 0", ex.Message);
    }

    [Fact]
    public void EveryKnownSection_RootAcceptsTheWholeTopology()
    {
        var services = new ServiceCollection();
        var config = Root(new Dictionary<string, string?>
        {
            ["CredProx:audit:enabled"] = "false", // casing must not matter
            ["CredProx:CallerAuth:Header"] = "X-API-Key",
            ["CredProx:Callers:app:Keys:0:key"] = "secret:k",
            ["CredProx:Connections:conn:ClientCertificate"] = "secret:c",
            ["CredProx:Credentials:cred:Type"] = "StaticKey",
            ["CredProx:Destinations:dest:Template"] = "https://vendor.example/",
            ["CredProx:Errors:Enabled"] = "false",
            ["CredProx:Errors:MaxNormalisedBodyBytes"] = "16384",
            ["CredProx:Health:enabled"] = "false",
            ["CredProx:KillSwitch:Clusters:0"] = "dest",
            ["CredProx:Presets:acme:TokenEndpoint"] = "https://id.acme.example/token",
            ["CredProx:Resilience:MaxRetries"] = "2",
            ["CredProx:Scrubbing:Enabled"] = "false",
            ["CredProx:Secrets:k"] = "v",
            ["CredProx:Throttling:PermitsPerInterval"] = "50",
        });

        services.AddReverseProxy().AddCredProx(config);

        Assert.NotNull(services);
    }

    // ---- helpers ----

    private static IConfiguration Root(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
}
