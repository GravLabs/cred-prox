using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the connections folder: the binder's unknown-key short-circuit
/// (startup and rebind — one labeled error, never a cascade), the rebind null guard, the
/// password-reference leg of the reuse condition, the registry's ordering and lookup
/// guard, the unloaded-certificate message, and the provider's constructor guards plus
/// the two rebind log lines.
/// </summary>
public sealed class ConnectionSurvivorTests
{
    private static (IConfiguration Config, ReloadableMemoryConfigurationProvider Reloadable) ConfigWith(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();
        return (config, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static ConnectionBinder Binder(IConfiguration config) =>
        new(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance);

    private static Dictionary<string, string?> PemConnection(string name = "contoso") => new()
    {
        [$"CredProx:Connections:{name}:ClientCertificate"] = $"secret:{name}-cert",
        [$"CredProx:Secrets:{name}-cert"] = TestCertificates.PemBundle(TestCertificates.CreateSelfSigned($"triage-{name}")),
    };

    [Fact]
    public void Bind_UnknownKey_ReportsOneErrorLabeledWithTheConnection()
    {
        // The unknown key short-circuits the whole section: no second 'no
        // ClientCertificate' error piled on top.
        var (config, _) = ConfigWith(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:Bogus"] = "x",
        });

        var ex = Assert.Throws<OptionsValidationException>(() => Binder(config).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("connection 'contoso'", failure, StringComparison.Ordinal);
        Assert.Contains("Bogus", failure, StringComparison.Ordinal);

        // The scope is quoted and exact: the full key path also embeds the section
        // prefix, so only this form distinguishes the scope argument from being emptied.
        Assert.Contains("under 'CredProx:Connections:contoso'", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Rebind_NullPrevious_Throws()
    {
        var (config, _) = ConfigWith(PemConnection());

        Assert.Throws<ArgumentNullException>(() => Binder(config).Rebind(null!));
    }

    [Fact]
    public void Rebind_UnknownKey_ReportsOnlyTheUnknownKey()
    {
        // The M17 rejection runs before the reuse path: the reload fails with exactly the
        // unknown-key error, never a second error from re-binding the same section.
        var (config, reloadable) = ConfigWith(PemConnection());
        var binder = Binder(config);
        var previous = binder.Bind();

        reloadable.Remove("CredProx:Connections:contoso:ClientCertificate");
        reloadable.Set("CredProx:Connections:contoso:Bogus", "x");
        reloadable.Reload();

        var ex = Assert.Throws<OptionsValidationException>(() => binder.Rebind(previous));

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("unknown configuration key", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Rebind_AddedPasswordReference_RebindsFresh_NotReused()
    {
        // The reuse condition has two legs: certificate reference AND password reference
        // unchanged. Adding a password changes the material contract — the connection
        // object must be rebuilt, not handed through with the old password wiring.
        var (config, reloadable) = ConfigWith(PemConnection());
        var binder = Binder(config);
        var previous = binder.Bind();
        var original = previous.Get("contoso");

        reloadable.Set("CredProx:Connections:contoso:ClientCertificatePassword", "secret:contoso-pw");
        reloadable.Set("CredProx:Secrets:contoso-pw", "irrelevant-unencrypted-key");
        reloadable.Reload();
        var rebound = binder.Rebind(previous);

        Assert.False(ReferenceEquals(original, rebound.Get("contoso")));
    }

    [Fact]
    public void Registry_NamesAreOrderedLikeConfigurationLookup()
    {
        var entries = new Dictionary<string, string?>();
        foreach (var (name, cert) in new[] { ("beta", "triage-beta"), ("Alpha", "triage-alpha") })
        {
            entries[$"CredProx:Connections:{name}:ClientCertificate"] = $"secret:{name}-cert";
            entries[$"CredProx:Secrets:{name}-cert"] =
                TestCertificates.PemBundle(TestCertificates.CreateSelfSigned(cert));
        }

        var (config, _) = ConfigWith(entries);

        var registry = Binder(config).Bind();

        Assert.Equal(["Alpha", "beta"], registry.Names);
    }

    [Fact]
    public void Registry_GetNull_ThrowsForItsOwnParameter()
    {
        var (config, _) = ConfigWith(PemConnection());
        var registry = Binder(config).Bind();

        var ex = Assert.Throws<ArgumentNullException>(() => registry.Get(null!));
        Assert.Equal("name", ex.ParamName);
    }

    [Fact]
    public void Connection_CertificateBeforeAnyLoad_NamesTheConnection()
    {
        // The startup binder guarantees a load; this is the contract message for any other
        // construction path.
        var connection = new ClientCertificateConnection(
            "lonely", secrets: null!, "secret:whatever", passwordReference: null, NullLogger.Instance);

        var ex = Assert.Throws<InvalidOperationException>(() => connection.Certificate);
        Assert.Equal("The connection 'lonely' has no loaded client certificate.", ex.Message);
    }

    // ---- provider ----

    private sealed class ManualChangeToken : IChangeToken
    {
        private Action<object?>? _callback;
        private object? _state;

        public bool ActiveChangeCallbacks => true;

        public bool HasChanged => false;

        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state)
        {
            _callback = callback;
            _state = state;
            return new NoopDisposable();
        }

        public void Fire() => _callback?.Invoke(_state);

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    private sealed class StubSecretSource(ManualChangeToken token) : ISecretSource
    {
        public string Scheme => "triage";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new((string?)null);

        public IChangeToken GetChangeToken() => token;
    }

    private static ConnectionBinder ValidBinder(out ReloadableMemoryConfigurationProvider reloadable)
    {
        var (config, provider) = ConfigWith(PemConnection());
        reloadable = provider;
        return Binder(config);
    }

    [Fact]
    public void Provider_ConstructorGuards()
    {
        var binder = ValidBinder(out _);
        var token = new ManualChangeToken();
        var secretSource = new StubSecretSource(token);
        ILogger<ConnectionRegistryProvider> logger = NullLogger<ConnectionRegistryProvider>.Instance;

        Assert.Throws<ArgumentNullException>(() => new ConnectionRegistryProvider(null!, secretSource, logger));
        Assert.Throws<ArgumentNullException>(() => new ConnectionRegistryProvider(binder, null!, logger));
        Assert.Throws<ArgumentNullException>(() => new ConnectionRegistryProvider(binder, secretSource, null!));
    }

    [Fact]
    public void Provider_SuccessfulRebind_LogsTheExactLine()
    {
        var binder = ValidBinder(out _);
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        _ = new ConnectionRegistryProvider(
            binder,
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<ConnectionRegistryProvider>());

        token.Fire();

        Assert.Contains(
            "CredProx connections rebound after a configuration change.",
            logs);
    }

    [Fact]
    public void Provider_FailedRebind_LogsTheExactLine_AndKeepsThePreviousRegistry()
    {
        var binder = ValidBinder(out var reloadable);
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        var provider = new ConnectionRegistryProvider(
            binder,
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<ConnectionRegistryProvider>());
        var serving = provider.Current.Get("contoso");

        // Emptied, not removed: a fully removed key would drop the section child and make
        // the reload a legitimate delete-all.
        reloadable.Set("CredProx:Connections:contoso:ClientCertificate", "");
        reloadable.Reload();
        token.Fire();

        Assert.Contains(
            "CredProx connections failed to rebind after a configuration change; keeping the previous registry.",
            logs);
        Assert.Same(serving, provider.Current.Get("contoso"));
    }

    [Fact]
    public void Bind_MissingClientCertificate_StatesTheMissingKeyInFull()
    {
        // The failure text is the operator's whole diagnosis: which connection, which
        // key. An empty failure entry would be operator-useless.
        var (config, _) = ConfigWith(new Dictionary<string, string?>
        {
            ["CredProx:Connections:ghost:ClientCertificate"] = " ",
        });

        var ex = Assert.Throws<OptionsValidationException>(() => Binder(config).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("The connection 'ghost' has no ClientCertificate.", failure, StringComparison.Ordinal);
    }
}
