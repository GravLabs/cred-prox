using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the pipeline class and the reverse-proxy wiring: the pipeline
/// guards its constructor inputs and its null-context entry points, and AddCredProx
/// actually registers the pieces the request path resolves at runtime — logging, the bound
/// core options, the default-clock audit recorder, the live kill-switch view, the replaced
/// forwarder client factory, and the feature/filter/hosted-service registrations.
/// </summary>
public sealed class WiringSurvivorTests
{
    private static IConfiguration Config(params (string Key, string Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => e.Key, e => (string?)e.Value))
            .Build();

    // ---- pipeline ----

    [Fact]
    public void Pipeline_GuardsItsConstructorInputs()
    {
        // The LINQ spread right below the guards is an absorber that names its own
        // parameter ("source"): only the paramName distinguishes our throw from it.
        var request = Assert.Throws<ArgumentNullException>(() => new CredProxPipeline(null!, [], []));
        Assert.Equal("requestFeatures", request.ParamName);

        var pipeline = Assert.Throws<ArgumentNullException>(() => new CredProxPipeline([], null!, []));
        Assert.Equal("pipelineFeatures", pipeline.ParamName);

        var response = Assert.Throws<ArgumentNullException>(() => new CredProxPipeline([], [], null!));
        Assert.Equal("responseFeatures", response.ParamName);
    }

    [Fact]
    public async Task Pipeline_NullContext_ThrowsOnBothDirections()
    {
        var pipeline = new CredProxPipeline([], [], []);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => pipeline.ApplyRequestAsync(null!, default).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => pipeline.ApplyResponseAsync(null!, default).AsTask());
    }

    // ---- wiring ----

    [Fact]
    public void AddCredProx_GuardsBothOverloads()
    {
        Assert.Throws<ArgumentNullException>(
            () => ((IReverseProxyBuilder)null!).AddCredProx());

        var builder = new ServiceCollection().AddReverseProxy();
        Assert.Throws<ArgumentNullException>(
            () => builder.AddCredProx((IConfiguration)null!));
    }

    private static ServiceProvider Wire(
        out IReverseProxyBuilder builder,
        params (string Key, string Value)[] entries)
    {
        var services = new ServiceCollection();
        var config = Config(entries);
        services.AddCredProxConfigurationSecrets(config);
        builder = services.AddReverseProxy();
        builder.AddCredProx(config);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void AddCredProx_RegistersWhatTheRequestPathResolves()
    {
        using var provider = Wire(out _, ("CredProx:InboundKeyHeader", "X-Triage-Inbound"));

        // Logging for the features and providers (a host without its own logging still works).
        Assert.NotNull(provider.GetRequiredService<ILoggerFactory>());

        // Core options bound from the CredProx section — the inbound header contract.
        Assert.Equal(
            "X-Triage-Inbound",
            provider.GetRequiredService<CredProxCoreOptions>().InboundKeyHeader);

        // The audit recorder resolves with no TimeProvider registered (the system clock).
        Assert.NotNull(provider.GetRequiredService<CredProxAuditRecorder>());

        // The live kill-switch view is resolvable as its own service (the transient wiring).
        Assert.NotNull(provider.GetRequiredService<KillSwitchRegistry>());

        // The forwarder client factory is CredProx's, not YARP's default.
        Assert.IsType<CredProxForwarderHttpClientFactory>(
            provider.GetRequiredService<IForwarderHttpClientFactory>());
    }

    [Fact]
    public void AddCredProxAuditRecorder_ObservesTheHostRegisteredTimeProvider()
    {
        // The recorder's clock is the host's when the host registers one (audit latency
        // then rides the host clock, and tests can drive it): removing the ?? left arm
        // silently pins the system clock instead.
        var services = new ServiceCollection();
        var fake = new FakeTimeProvider();
        services.AddSingleton<TimeProvider>(fake);
        var config = Config();
        services.AddCredProxConfigurationSecrets(config);
        services.AddReverseProxy().AddCredProx(config);
        using var provider = services.BuildServiceProvider();

        var recorder = provider.GetRequiredService<CredProxAuditRecorder>();
        var time = typeof(CredProxAuditRecorder)
            .GetField("_time", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(recorder);

        Assert.Same(fake, time);
    }

    [Fact]
    public void AddCredProx_RegistersTheBuiltInExtensions()
    {
        Wire(out var builder);

        bool Registered<T>(System.Type implementation) => ((IServiceCollection)builder.Services)
            .Any(d => d.ServiceType == typeof(T) && d.ImplementationType == implementation);

        Assert.True(Registered<IPartitionSourceFactory>(typeof(HeaderPartitionSourceFactory)));
        Assert.True(Registered<IRequestFeature>(typeof(HmacSignFeature)));
        Assert.True(Registered<IHttpMessageHandlerBuilderFilter>(typeof(CredProxTokenClientFilter)));
        Assert.True(Registered<IHostedService>(typeof(CredProxStartupValidator)));
    }

    [Fact]
    public void AddCredProx_NonPositiveErrorCap_RefusesStartup()
    {
        var services = new ServiceCollection();
        var config = Config(("CredProx:Errors:MaxNormalisedBodyBytes", "0"));
        services.AddCredProxConfigurationSecrets(config);
        var builder = services.AddReverseProxy();

        var ex = Assert.Throws<OptionsValidationException>(() => builder.AddCredProx(config));

        var failure = Assert.Single(ex.Failures);
        Assert.Equal("CredProx:Errors:MaxNormalisedBodyBytes must be greater than 0.", failure);
    }
}
