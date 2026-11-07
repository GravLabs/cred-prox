using System.Diagnostics.CodeAnalysis;
using System.Net;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Testing;

/// <summary>
/// The conformance suite every credential provider should pass (see
/// <c>docs/credprox-plan.md</c> §5 "Testing kit"): inherit it from a test class, describe
/// the credential in configuration, and the no-secret-in-logs and failure-hygiene checks
/// from §5.2 run against your provider through the real binder, secret scoping and token
/// cache wiring — the same suites the built-ins run.
/// </summary>
/// <remarks>
/// A provider that caches through <see cref="ITokenCache"/> (the OAuth-style contract)
/// should inherit <see cref="CachingCredentialProviderConformanceTests{TProvider,TOptions}"/>
/// instead, which adds the single-flight and refresh-after-invalidate checks.
/// </remarks>
/// <typeparam name="TProvider">The provider under test.</typeparam>
/// <typeparam name="TOptions">Its options type.</typeparam>
[Experimental("CREDPROX001")]
public abstract class CredentialProviderConformanceTests<TProvider, TOptions>
    where TProvider : class, ICredentialProvider<TOptions>
    where TOptions : class
{
    /// <summary>The name the credential is bound under.</summary>
    protected const string CredentialName = "conformance";

    /// <summary>The configuration <c>Type</c> name the provider is registered under.</summary>
    protected abstract string CredentialTypeName { get; }

    /// <summary>
    /// The credential's configuration — keys relative to
    /// <c>CredProx:Credentials:conformance</c> (include <c>Type</c>).
    /// </summary>
    protected abstract IReadOnlyDictionary<string, string?> CredentialConfig { get; }

    /// <summary>Secret values for the suite — keys relative to <c>CredProx:Secrets</c>.</summary>
    protected virtual IReadOnlyDictionary<string, string?> SecretConfig =>
        new Dictionary<string, string?>();

    /// <summary>
    /// Every literal secret value configured above; the suite asserts none of them ever
    /// appears in a log line or an error message.
    /// </summary>
    protected abstract IReadOnlyList<string> SecretValues { get; }

    /// <summary>The partition value the suite acquires with; <see langword="null"/> when unpartitioned.</summary>
    protected virtual string? Partition => null;

    /// <summary>Hook for extra service registrations (a fake <see cref="TimeProvider"/> and friends).</summary>
    /// <param name="services">The host's service collection, after CredProx's own registrations.</param>
    protected virtual void ConfigureServices(IServiceCollection services)
    {
    }

    /// <summary>
    /// Builds the per-request context the suite acquires with. Override for delegated
    /// credential types (<c>IRequiresInboundToken</c>, §3.6) to carry an inbound token.
    /// </summary>
    /// <returns>The context every <see cref="ConformanceHost.Acquire"/> uses.</returns>
    protected virtual CredentialRequestContext CreateContext() => new()
    {
        CredentialName = CredentialName,
        Partition = Partition,
    };

    /// <summary>
    /// Sets defaults on the fake token server (a path-routing <see cref="FakeTokenServer.Responder"/>
    /// and friends) before the per-test <c>configureTokenServer</c> runs, so a test's explicit
    /// script still wins.
    /// </summary>
    /// <param name="tokenServer">The host's fake token server.</param>
    protected virtual void ConfigureTokenServer(FakeTokenServer tokenServer)
    {
    }

    /// <summary>A built conformance host: bound credential, recording fakes, captured logs.</summary>
    protected sealed class ConformanceHost : IAsyncDisposable
    {
        internal ConformanceHost(
            ServiceProvider services,
            CredentialBinding binding,
            FakeTokenServer tokenServer,
            CapturedLogSink logs,
            CredentialRequestContext context)
        {
            Services = services;
            Binding = binding;
            TokenServer = tokenServer;
            Logs = logs;
            Context = context;
        }

        /// <summary>The built provider container.</summary>
        public ServiceProvider Services { get; }

        /// <summary>The bound credential binding under test.</summary>
        public CredentialBinding Binding { get; }

        /// <summary>The fake token endpoint the provider's HTTP calls reach.</summary>
        public FakeTokenServer TokenServer { get; }

        /// <summary>Everything the host logged.</summary>
        public CapturedLogSink Logs { get; }

        /// <summary>The per-request context the suite acquires with.</summary>
        public CredentialRequestContext Context { get; }

        /// <summary>The token cache the invalidation checks drive.</summary>
        public ITokenCache Cache => Services.GetRequiredService<ITokenCache>();

        /// <summary>Acquires the credential value through the bound provider.</summary>
        /// <param name="cancellationToken">Cancels the acquisition.</param>
        public ValueTask<string> Acquire(CancellationToken cancellationToken = default) =>
            Binding.GetCredential(Context, cancellationToken);

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            Services.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Binds the credential through the real <see cref="CredentialBinder"/> over the
    /// configured inputs, with token HTTP calls landing on a <see cref="FakeTokenServer"/>
    /// and every log line captured.
    /// </summary>
    /// <param name="configureTokenServer">Scripts the token server before the test runs.</param>
    /// <param name="configureConfig">Mutates the composed configuration keys (for failure setups).</param>
    protected ConformanceHost BuildHost(
        Action<FakeTokenServer>? configureTokenServer = null,
        Action<Dictionary<string, string?>>? configureConfig = null)
    {
        var keys = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in CredentialConfig)
        {
            keys[$"CredProx:Credentials:{CredentialName}:{key}"] = value;
        }

        foreach (var (key, value) in SecretConfig)
        {
            keys[$"CredProx:Secrets:{key}"] = value;
        }

        configureConfig?.Invoke(keys);

        var tokenServer = new FakeTokenServer();
        ConfigureTokenServer(tokenServer);
        configureTokenServer?.Invoke(tokenServer);
        var logs = new CapturedLogSink();

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(keys).Build();
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Trace);
            builder.AddProvider(logs);
        });
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxCredentialType<TProvider, TOptions>(CredentialTypeName);
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(tokenServer));
        ConfigureServices(services);

        var provider = services.BuildServiceProvider();
        var binding = provider.GetRequiredService<CredentialRegistry>().Get(CredentialName);
        return new ConformanceHost(provider, binding, tokenServer, logs, CreateContext());
    }

    /// <summary>The configured inputs must actually produce a credential value.</summary>
    [Fact]
    public async Task Acquire_SucceedsWithConfiguredInputs()
    {
        await using var host = BuildHost();

        var value = await host.Acquire();

        Assert.False(string.IsNullOrEmpty(value));
        host.Logs.AssertNoSecretValues(SecretValues);
    }

    /// <summary>§5.2 "Diagnostics": secret values never appear in logs at any level.</summary>
    [Fact]
    public async Task SecretValues_NeverAppearInLogs()
    {
        await using var host = BuildHost();

        await host.Acquire();

        host.Logs.AssertNoSecretValues(SecretValues);
    }

    /// <summary>
    /// §5.2 failure hygiene: when acquisition fails, neither the thrown message nor the
    /// logs may contain a secret value. The default drives failure from the token server;
    /// providers that never touch HTTP override this with their own failure shape.
    /// </summary>
    [Fact]
    public virtual async Task Failure_DoesNotLeakSecretValues()
    {
        await using var host = BuildHost(server =>
            server.Enqueue(HttpStatusCode.InternalServerError, """{"error":"server_error"}"""));

        var failure = await Assert.ThrowsAnyAsync<Exception>(() => host.Acquire().AsTask());

        foreach (var value in SecretValues.Where(v => !string.IsNullOrEmpty(v)))
        {
            Assert.DoesNotContain(value, failure.Message, StringComparison.Ordinal);
        }

        host.Logs.AssertNoSecretValues(SecretValues);
    }
}
