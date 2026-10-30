using System.Net.Http;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Proves the pipeline orders features by their declared <see cref="Stage"/> regardless
/// of the order they were registered in (plan §3.5 rule 3).
/// </summary>
public class StageOrderingTests
{
    private sealed class RecordingRequestFeature(Stage stage, string name, List<string> log) : IRequestFeature
    {
        public Stage Stage { get; } = stage;

        public string Name { get; } = name;

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            log.Add(Name);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class NamedPipelineFeature(Stage stage, string name) : IPipelineFeature
    {
        public Stage Stage { get; } = stage;

        public string Name { get; } = name;

        public DelegatingHandler CreateHandler(DelegatingHandler innerHandler) => innerHandler;
    }

    private sealed class RecordingResponseFeature(Stage stage, string name, List<string> log) : IResponseFeature
    {
        public Stage Stage { get; } = stage;

        public string Name { get; } = name;

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            log.Add(Name);
            return ValueTask.CompletedTask;
        }
    }

    // Implements only ApplyAsync: its Stage is the interface default (ShapeResponse, M20).
    private sealed class DefaultStageResponseFeature(string name, List<string> log) : IResponseFeature
    {
        public string Name { get; } = name;

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            log.Add(Name);
            return ValueTask.CompletedTask;
        }
    }

    private static readonly Stage[] PlanOrder =
    [
        Stage.AuthenticateCaller,
        Stage.ApplyKillSwitch,
        Stage.AuthorizeOperation,
        Stage.ResolveDestination,
        Stage.ApplyCallerBudget,
        Stage.ShapeHeaders,
        Stage.AttachCredential,
        Stage.Sign,
        Stage.Pipeline,
        Stage.Send,
        Stage.ShapeResponse,
    ];

    [Fact]
    public void StageValues_AreAscendingInPlanOrder()
    {
        var values = Enum.GetValues<Stage>();
        Assert.Equal(PlanOrder, values);
        Assert.Equal(values.OrderBy(v => (int)v), values);
    }

    [Fact]
    public void RequestFeatures_AreOrderedByStage_RegardlessOfRegistrationOrder()
    {
        var log = new List<string>();

        // Registered in a deliberately scrambled order.
        var pipeline = new CredProxPipeline(
            [
                new RecordingRequestFeature(Stage.Sign, "sign", log),
                new RecordingRequestFeature(Stage.AuthenticateCaller, "authenticate", log),
                new RecordingRequestFeature(Stage.AttachCredential, "attach", log),
                new RecordingRequestFeature(Stage.ResolveDestination, "destination", log),
                new RecordingRequestFeature(Stage.ShapeHeaders, "headers", log),
                new RecordingRequestFeature(Stage.AuthorizeOperation, "authorize", log),
            ],
            []);

        Assert.Equal(
            [Stage.AuthenticateCaller, Stage.AuthorizeOperation, Stage.ResolveDestination, Stage.ShapeHeaders, Stage.AttachCredential, Stage.Sign],
            pipeline.RequestFeatures.Select(f => f.Stage));
    }

    [Fact]
    public async Task ApplyRequestAsync_RunsFeaturesInStageOrder()
    {
        var log = new List<string>();
        var pipeline = new CredProxPipeline(
            [
                new RecordingRequestFeature(Stage.Sign, "sign", log),
                new RecordingRequestFeature(Stage.AuthenticateCaller, "authenticate", log),
                new RecordingRequestFeature(Stage.AttachCredential, "attach", log),
                new RecordingRequestFeature(Stage.ShapeHeaders, "headers", log),
            ],
            []);

        await pipeline.ApplyRequestAsync(new DefaultHttpContext(), CancellationToken.None);

        Assert.Equal(["authenticate", "headers", "attach", "sign"], log);
    }

    [Fact]
    public void FeaturesWithTheSameStage_KeepRegistrationOrder()
    {
        var log = new List<string>();
        var pipeline = new CredProxPipeline(
            [
                new RecordingRequestFeature(Stage.ShapeHeaders, "second", log),
                new RecordingRequestFeature(Stage.ShapeHeaders, "first-registered", log),
                new RecordingRequestFeature(Stage.AuthenticateCaller, "before", log),
            ],
            []);

        Assert.Equal(
            ["before", "second", "first-registered"],
            pipeline.RequestFeatures.Cast<RecordingRequestFeature>().Select(f => f.Name));
    }

    [Fact]
    public void PipelineFeatures_AreOrderedByStage_RegardlessOfRegistrationOrder()
    {
        var pipeline = new CredProxPipeline(
            [],
            [
                new NamedPipelineFeature(Stage.Pipeline, "audit"),
                new NamedPipelineFeature(Stage.Sign, "sign"),
                new NamedPipelineFeature(Stage.Pipeline, "throttle"),
            ]);

        Assert.Equal(["sign", "audit", "throttle"], pipeline.PipelineFeatures.Cast<NamedPipelineFeature>().Select(f => f.Name));
    }

    [Fact]
    public void EmptyRegistration_ProducesEmptyOrderedPipeline()
    {
        var pipeline = new CredProxPipeline([], []);

        Assert.Empty(pipeline.RequestFeatures);
        Assert.Empty(pipeline.PipelineFeatures);
        Assert.Empty(pipeline.ResponseFeatures);
    }

    [Fact]
    public void ResponseFeature_WithoutDeclaredStage_DefaultsToShapeResponse()
    {
        var feature = new DefaultStageResponseFeature("default", []);

        // DIM members are reached through the interface.
        Assert.Equal(Stage.ShapeResponse, ((IResponseFeature)feature).Stage);
    }

    [Fact]
    public async Task ApplyResponseAsync_RunsFeaturesInStageOrder()
    {
        var log = new List<string>();
        var pipeline = new CredProxPipeline(
            [],
            [],
            [
                new RecordingResponseFeature(Stage.ShapeResponse, "second", log),
                new DefaultStageResponseFeature("third-default", log),
                new RecordingResponseFeature(Stage.Sign, "early-escape-hatch", log),
            ]);

        await pipeline.ApplyResponseAsync(new DefaultHttpContext(), CancellationToken.None);

        // Same rule as the request side: stage order wins; equal stages keep
        // registration order (the two ShapeResponse ones).
        Assert.Equal(["early-escape-hatch", "second", "third-default"], log);
    }
}
