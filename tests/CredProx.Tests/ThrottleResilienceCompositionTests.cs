using System.Reflection;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M8 chain composition (§8.4, design note): the outbound pipeline is
/// throttle → resilience → token-refresh → transport, deterministic regardless of
/// feature registration order — first processed is innermost, so resilience (Order 0)
/// wraps the refresh handler and throttling (Order 10) wraps resilience. One throttle
/// permit therefore covers every resilience retry.
/// </summary>
public sealed class ThrottleResilienceCompositionTests
{
    private static HttpMessageHandler Compose(params IPipelineFeature[] features)
    {
        var collection = new ServiceCollection();
        collection.AddSingleton<IOptions<RefreshOn401Options>>(Options.Create(new RefreshOn401Options()));
        foreach (var feature in features)
        {
            collection.AddSingleton(feature);
        }

        var factory = new CredProxForwarderHttpClientFactory(collection.BuildServiceProvider());
        return factory.ComposePipeline(
            new ForwarderHttpClientContext { ClusterId = "cluster-9" },
            new StubTransport());
    }

    private sealed class StubTransport : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }

    private static IEnumerable<HttpMessageHandler> Chain(HttpMessageHandler outermost)
    {
        var innerHandler = typeof(DelegatingHandler)
            .GetProperty("InnerHandler", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!;
        for (HttpMessageHandler? current = outermost; current is not null;)
        {
            yield return current;
            current = current is DelegatingHandler ? (HttpMessageHandler?)innerHandler.GetValue(current) : null;
        }
    }

    private static (CredProxThrottleFeature Throttle, CredProxResilienceFeature Resilience) BuiltInFeatures()
    {
        var time = new FakeTimeProvider();
        var throttle = new CredProxThrottleFeature(new ClusterThrottleRegistry(new ThrottleOptions(), time), time);
        var resilience = new CredProxResilienceFeature(new ClusterResilienceRegistry(new ResilienceOptions()));
        return (throttle, resilience);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)] // registration order must not change the chain
    public void BuiltInChain_ThrottleOutsideResilienceOutsideRefresh(bool resilienceRegisteredFirst)
    {
        var (throttle, resilience) = BuiltInFeatures();
        var features = resilienceRegisteredFirst
            ? new IPipelineFeature[] { resilience, throttle }
            : new IPipelineFeature[] { throttle, resilience };

        var chain = Chain(Compose(features)).ToArray();

        Assert.IsType<ThrottleHandler>(chain[0]);
        Assert.IsType<CredProxResilienceHandler>(chain[1]);
        Assert.IsType<TokenRefreshHandler>(chain[2]);
        Assert.IsType<StubTransport>(chain[3]);
    }

    [Fact]
    public void ClusterScopedFeatures_RejectTheContextlessOverload()
    {
        var (throttle, resilience) = BuiltInFeatures();

        Assert.Throws<InvalidOperationException>(() => throttle.CreateHandler(new PassThrough()));
        Assert.Throws<InvalidOperationException>(() => resilience.CreateHandler(new PassThrough()));
    }

    [Fact]
    public void BuiltInOrders_ResilienceInnermostOfTheTwo()
    {
        var (throttle, resilience) = BuiltInFeatures();

        Assert.Equal(Stage.Pipeline, throttle.Stage);
        Assert.Equal(Stage.Pipeline, resilience.Stage);
        Assert.True(resilience.Order < throttle.Order);
    }

    private sealed class PassThrough : DelegatingHandler
    {
    }
}

/// <summary>
/// <c>AddCredProxThrottling</c> / <c>AddCredProxResilience</c> (§8.4): features register,
/// and nonsense limits fail fast at startup through the options validators.
/// </summary>
public sealed class ThrottleResilienceRegistrationTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    [Fact]
    public void AddThrottling_RegistersFeatureAndRegistry()
    {
        var services = new ServiceCollection();
        services.AddCredProxThrottling(Config(("CredProx:Throttling:PermitsPerInterval", "10")));

        var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<ClusterThrottleRegistry>());
        Assert.Contains(
            provider.GetServices<IPipelineFeature>(),
            f => f is CredProxThrottleFeature);
    }

    [Fact]
    public void AddResilience_RegistersFeatureAndRegistry()
    {
        var services = new ServiceCollection();
        services.AddCredProxResilience(Config(("CredProx:Resilience:MaxRetries", "2")));

        var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<ClusterResilienceRegistry>());
        Assert.Contains(
            provider.GetServices<IPipelineFeature>(),
            f => f is CredProxResilienceFeature);
    }

    [Fact]
    public void AddThrottling_NegativeLimit_ThrowsAtStartup()
    {
        var services = new ServiceCollection();
        Assert.Throws<OptionsValidationException>(() =>
            services.AddCredProxThrottling(Config(("CredProx:Throttling:PermitsPerInterval", "-1"))));
    }

    [Fact]
    public void AddResilience_BadFailureRatio_ThrowsAtStartup()
    {
        var services = new ServiceCollection();
        Assert.Throws<OptionsValidationException>(() =>
            services.AddCredProxResilience(Config(("CredProx:Resilience:FailureRatio", "2"))));
    }

    [Fact]
    public void ThrottleValidator_AcceptsDefaultsAndFlagsPerClusterNonsense()
    {
        var validator = new ThrottleOptionsValidator();
        Assert.True(validator.Validate(null, new ThrottleOptions()).Succeeded);

        var options = new ThrottleOptions();
        options.Clusters["c"] = new ThrottleClusterOptions
        {
            QueueLimit = -1,
            Interval = TimeSpan.Zero,
            MaxQueueWait = TimeSpan.Zero,
            MaxPause = TimeSpan.Zero,
        };
        var result = validator.Validate(null, options);
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Clusters:c:QueueLimit", StringComparison.Ordinal));
        Assert.Contains(result.Failures, f => f.Contains("Clusters:c:Interval", StringComparison.Ordinal));
        Assert.Contains(result.Failures, f => f.Contains("Clusters:c:MaxQueueWait", StringComparison.Ordinal));
        Assert.Contains(result.Failures, f => f.Contains("Clusters:c:MaxPause", StringComparison.Ordinal));
    }

    [Fact]
    public void AddThrottling_ZeroClusterInterval_ThrowsAtStartup()
    {
        // A zero cluster Interval used to throw ArgumentOutOfRangeException at the first
        // request's state creation; it must fail startup like every other bad config.
        var services = new ServiceCollection();
        Assert.Throws<OptionsValidationException>(() =>
            services.AddCredProxThrottling(Config(("CredProx:Throttling:Clusters:c:Interval", "00:00:00"))));
    }

    [Fact]
    public void ResilienceValidator_AcceptsDefaultsAndFlagsPerClusterNonsense()
    {
        var validator = new ResilienceOptionsValidator();
        Assert.True(validator.Validate(null, new ResilienceOptions()).Succeeded);

        var options = new ResilienceOptions();
        options.Clusters["c"] = new ResilienceClusterOptions { AttemptTimeout = TimeSpan.Zero };
        var result = validator.Validate(null, options);
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Clusters:c:AttemptTimeout", StringComparison.Ordinal));
    }
}
