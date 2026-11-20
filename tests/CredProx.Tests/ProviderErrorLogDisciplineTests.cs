using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M45 security finding F-5: the catch-alls at the credential provider boundaries report
/// the exception's <em>type</em>, never the provider's own message text. A provider at
/// these seams may be a third party, and its message is its own — it can carry a secret
/// value the operator must never see. The exception object is no safer channel: every
/// real log provider renders an attached exception in full. The instrument here records
/// the formatted message <em>and</em> appends the exception text when one is attached
/// (<see cref="CapturingLoggerProvider"/>), so both leak channels are observable.
/// </summary>
public sealed class ProviderErrorLogDisciplineTests
{
    private const string Sentinel = "LEAKED-VALUE-9133";

    private static (ILoggerFactory Factory, List<string?> Logs) Capture()
    {
        var logs = new List<string?>();
        var factory = LoggerFactory.Create(b => b.AddProvider(new CapturingLoggerProvider(logs)));
        return (factory, logs);
    }

    private static string Joined(List<string?> logs) => string.Join(" // ", logs);

    // ---- the attach feature's obtain catch-all ----------------------------------------

    public sealed class ThrowingAttachOptions
    {
    }

    /// <summary>The third-party shape: an obtain failure whose message carries a value.</summary>
    public sealed class ThrowingAttachProvider : ICredentialProvider<ThrowingAttachOptions>
    {
        public string Type => "ThrowingAttach";

        public ValueTask<string> GetCredentialAsync(
            ThrowingAttachOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"mint failed, carried value {Sentinel}");
    }

    [Fact]
    public async Task AttachObtainFailure_LogsExceptionType_NeverProviderText()
    {
        var (factory, logs) = Capture();
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:contoso:Type", "ThrowingAttach"));
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentialType<ThrowingAttachProvider, ThrowingAttachOptions>("ThrowingAttach");
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ILoggerFactory>(factory);
        var provider = services.BuildServiceProvider();
        var feature = new CredentialAttachFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            provider.GetRequiredService<ITokenCache>(),
            factory.CreateLogger<CredentialAttachFeature>());

        var context = M4Contexts.Create(out _, new Dictionary<string, string>
        {
            [CredProxMetadata.Credential] = "contoso",
        });
        await feature.ApplyAsync(context, default);

        // The caller still gets the static problem response; only the operator-facing
        // line changed: the kind of failure, not the provider's text.
        Assert.Equal(502, context.Response.StatusCode);
        Assert.Contains("could not be obtained", Joined(logs), StringComparison.Ordinal);
        Assert.Contains("InvalidOperationException", Joined(logs), StringComparison.Ordinal);
        Assert.DoesNotContain(Sentinel, Joined(logs), StringComparison.Ordinal);
        factory.Dispose();
    }

    // ---- the HMAC sign feature's obtain catch-all --------------------------------------

    [Fact]
    public async Task HmacObtainFailure_LogsExceptionType_NeverProviderText()
    {
        var (factory, logs) = Capture();
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:signer:Type", "Hmac"),
            ("CredProx:Credentials:signer:Secret", "secret:hmac-key"),
            ("CredProx:Credentials:signer:SignatureHeader", "X-Signature"),
            ("CredProx:Credentials:signer:Components:0", "method"),
            ("CredProx:Secrets:hmac-key", "key-value"));
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxHmac();
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ILoggerFactory>(factory);
        var provider = services.BuildServiceProvider();
        var registryProvider = provider.GetRequiredService<CredentialRegistryProvider>();

        // Swap in the third-party shape: the same binding, obtaining through a provider
        // whose message carries a value (same in-instrument swap the HMAC feature's
        // own guard tests use).
        typeof(CredentialRegistryProvider)
            .GetField("_current", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(registryProvider, new CredentialRegistry(new Dictionary<string, CredentialBinding>(StringComparer.OrdinalIgnoreCase)
            {
                ["signer"] = new CredentialBinding
                {
                    Name = "signer",
                    TypeName = "Hmac",
                    Options = new HmacOptions { Components = ["method"], SignatureHeader = "X-Signature" },
                    GetCredential = static (_, _) =>
                        throw new InvalidOperationException($"key fetch carried value {Sentinel}"),
                },
            }));

        var feature = new HmacSignFeature(
            registryProvider, TimeProvider.System, factory.CreateLogger<HmacSignFeature>());
        var context = M4Contexts.Create(out _, new Dictionary<string, string>
        {
            [CredProxMetadata.Credential] = "signer",
        });
        await feature.ApplyAsync(context, default);

        Assert.Equal(502, context.Response.StatusCode);
        Assert.Contains("could not be obtained", Joined(logs), StringComparison.Ordinal);
        Assert.Contains("InvalidOperationException", Joined(logs), StringComparison.Ordinal);
        Assert.DoesNotContain(Sentinel, Joined(logs), StringComparison.Ordinal);
        factory.Dispose();
    }

    // ---- the health probe's failure description -----------------------------------------

    public sealed class ThrowingProbeOptions
    {
    }

    public sealed class ThrowingProbeProvider : ICredentialProvider<ThrowingProbeOptions>
    {
        public string Type => "ThrowingProbe";

        public ValueTask<string> GetCredentialAsync(
            ThrowingProbeOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"exchange failed, carried value {Sentinel}");
    }

    [Fact]
    public async Task HealthProbeFailure_DescribesExceptionType_NeverProviderText()
    {
        var (factory, logs) = Capture();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:probe-cred:Type"] = "ThrowingProbe",
        }).Build();
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentialType<ThrowingProbeProvider, ThrowingProbeOptions>("ThrowingProbe");
        services.AddCredProxCredentials(config);
        services.AddSingleton<ILoggerFactory>(factory);
        var provider = services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>();

        var probe = new TokenObtainableProbe(provider, factory.CreateLogger<TokenObtainableProbe>());
        var result = await probe.CheckAsync(default);

        // The health report is surfaced through the health endpoint — the same channel
        // discipline as the log.
        Assert.NotNull(result);
        Assert.Contains("could not be obtained", result.Description!, StringComparison.Ordinal);
        Assert.Contains("InvalidOperationException", result.Description!, StringComparison.Ordinal);
        Assert.DoesNotContain(Sentinel, result.Description!, StringComparison.Ordinal);
        Assert.DoesNotContain(Sentinel, Joined(logs), StringComparison.Ordinal);
        factory.Dispose();
    }

    // ---- the credential registry's rebind catch-all -------------------------------------

    [Fact]
    public void RebindFailure_LogsOneLineNamingTheExceptionType_NoProviderText()
    {
        var (factory, logs) = Capture();
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>());
        var config = new ConfigurationBuilder().Add(source).Build();
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddSingleton<ILoggerFactory>(factory);
        _ = services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>();

        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        reloadable.Set("CredProx:Credentials:broken:Type", "NoSuchType"); // unknown type
        reloadable.Reload();

        // Exactly one line: no exception object is attached, so no provider renders its
        // text (a real provider appends every attached exception in full). The line names
        // the failure kind — a message that still carried the binder's own text would
        // name the missing type.
        var line = Assert.Single(logs);
        Assert.Contains("failed to rebind after a configuration change (", line, StringComparison.Ordinal);
        Assert.Contains("); keeping the previous registry.", line, StringComparison.Ordinal);
        Assert.DoesNotContain("NoSuchType", line, StringComparison.Ordinal);
        factory.Dispose();
    }
}
