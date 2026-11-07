using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
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
        services.AddReverseProxy().AddCredProx();
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.Sign));
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.AuthenticateCaller));
        services.AddSingleton<IRequestFeature>(new StubRequestFeature(Stage.AttachCredential));

        using var provider = services.BuildServiceProvider();
        var pipeline = provider.GetRequiredService<CredProxPipeline>();

        Assert.Equal(
            [Stage.AuthenticateCaller, Stage.AttachCredential, Stage.Sign],
            pipeline.RequestFeatures.Select(f => f.Stage));
    }

    [Fact]
    public void AddCredProx_WithNoFeaturesRegistered_ProducesEmptyPipeline()
    {
        var services = new ServiceCollection();
        services.AddReverseProxy().AddCredProx();

        using var provider = services.BuildServiceProvider();
        var pipeline = provider.GetRequiredService<CredProxPipeline>();

        Assert.Empty(pipeline.RequestFeatures);
        Assert.Empty(pipeline.PipelineFeatures);
    }
}
