using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Proves the <c>AddCredProx</c> entry point registers the stage-ordered pipeline and
/// that the pipeline resolves the registered features in stage order through DI.
/// </summary>
public class CredProxEntryTests
{
    private sealed class StubRequestFeature(Stage stage) : IRequestFeature
    {
        public Stage Stage { get; } = stage;

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;
    }

    [Fact]
    public void AddCredProx_RegistersPipeline_AndChains()
    {
        var services = new ServiceCollection();
        services.AddCredProx(new ConfigurationBuilder().Build());
        var builder = services.AddReverseProxy();

        var returned = builder.AddCredProx();

        Assert.Same(builder, returned);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<CredProxPipeline>());
    }

    [Fact]
    public void AddCredProx_PipelineOrdersRegisteredFeatures_ByStageNotRegistrationOrder()
    {
        var services = new ServiceCollection();
        services.AddCredProx(new ConfigurationBuilder().Build());
        services.AddReverseProxy().AddCredProx();
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.Sign));
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.AuthenticateCaller));
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.AttachCredential));

        using var provider = services.BuildServiceProvider();
        var pipeline = provider.GetRequiredService<CredProxPipeline>();

        // The leg now runs through the entry, so the pipeline also carries the core's
        // own features: the assertion is the stage-order invariant through DI, plus the
        // three stubs present. (The empty-pipeline contract lives in
        // StageOrderingTests.EmptyRegistration_ProducesEmptyOrderedPipeline.)
        var stages = pipeline.RequestFeatures.Select(f => f.Stage).ToArray();
        Assert.Equal(stages.OrderBy(s => s), stages);
        Assert.Contains(Stage.AuthenticateCaller, stages);
        Assert.Contains(Stage.AttachCredential, stages);
        Assert.Contains(Stage.Sign, stages);
    }
}
