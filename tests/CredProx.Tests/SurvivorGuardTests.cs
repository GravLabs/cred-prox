using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (guards): entry guards on types the composition tests only ever
/// build with live arguments. Each removal survives a full suite until a paramName pin
/// distinguishes the documented refusal from whatever the accident downstream throws.
/// </summary>
public sealed class SurvivorGuardTests
{
    private sealed class StubPartitionSource : IPartitionSource
    {
        public string Scheme => "stub";

        public PartitionRejection Rejection => PartitionRejection.BadRequest;

        public ValueTask<string?> GetPartitionAsync(
            Microsoft.AspNetCore.Http.HttpContext context,
            CancellationToken cancellationToken) => new((string?)null);
    }

    private sealed class ProbeForwarderFactory(IServiceProvider services) : CredProxForwarderHttpClientFactory(services)
    {
        public HttpMessageHandler Wrap(ForwarderHttpClientContext context, HttpMessageHandler handler) =>
            WrapHandler(context, handler);
    }

    private static ServiceProvider EmptyServices() => new ServiceCollection().BuildServiceProvider();

    [Fact]
    public void AuditRecorder_NullSinks_Throws_NamingSinks()
    {
        var error = Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            null!,
            new CredProxAuditOptions(),
            TimeProvider.System,
            NullLogger<CredProxAuditRecorder>.Instance,
            new CredProxCoreOptions(),
            callerKeyOptions: null));

        Assert.Equal("sinks", error.ParamName);
    }

    [Fact]
    public void ForwarderFactory_ComposePipeline_Guards_NameTheirParameters()
    {
        var factory = new CredProxForwarderHttpClientFactory(EmptyServices());
        var context = new ForwarderHttpClientContext();

        var noContext = Assert.Throws<ArgumentNullException>(
            () => factory.ComposePipeline(null!, new HttpClientHandler()));
        var noInner = Assert.Throws<ArgumentNullException>(
            () => factory.ComposePipeline(context, null!));

        Assert.Equal("context", noContext.ParamName);
        Assert.Equal("inner", noInner.ParamName);
    }

    [Fact]
    public void ForwarderFactory_WrapHandler_Guards_NameTheirParameters()
    {
        // The protected YARP seam guards before composing; a removal turns a host
        // contract violation into an opaque NRE from inside the pipeline build.
        var factory = new ProbeForwarderFactory(EmptyServices());
        var context = new ForwarderHttpClientContext();

        var noContext = Assert.Throws<ArgumentNullException>(() => factory.Wrap(null!, new HttpClientHandler()));
        var noHandler = Assert.Throws<ArgumentNullException>(() => factory.Wrap(context, null!));

        Assert.Equal("context", noContext.ParamName);
        Assert.Equal("handler", noHandler.ParamName);
    }

    [Fact]
    public void HeaderPartitionSourceFactory_NullArgument_ThrowsArgumentNull_NamingArgument()
    {
        // "header:" with no header name is a config bug; it must refuse at factory time,
        // not build a source that reads an unnamed header forever.
        var factory = new HeaderPartitionSourceFactory();

        var error = Assert.Throws<ArgumentNullException>(() => factory.CreateSource(null!));

        Assert.Equal("argument", error.ParamName);
    }

    [Fact]
    public void HeaderPartitionSourceFactory_EmptyArgument_ThrowsArgument_NamingArgument()
    {
        var factory = new HeaderPartitionSourceFactory();

        var error = Assert.Throws<ArgumentException>(() => factory.CreateSource(string.Empty));

        Assert.Equal("argument", error.ParamName);
    }

    [Fact]
    public async Task PartitionSourceBinding_Resolve_NullContext_Throws_NamingContext()
    {
        var binding = new PartitionSourceBinding(new StubPartitionSource(), ["tenant-a"], "header: X-Tenant");

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => binding.ResolveAsync(null!, default).AsTask());

        Assert.Equal("context", error.ParamName);
    }

    [Fact]
    public void FixedWindowRateLimiter_NegativeQueueLimit_Throws()
    {
        // A negative queue is "no waiters ever", not "unlimited" — the guard keeps the
        // option surface honest (M31 :32 triage).
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new FixedWindowRateLimiter(1, TimeSpan.FromMinutes(1), -1, TimeProvider.System));

        Assert.Equal("queueLimit", error.ParamName);
    }

    [Fact]
    public void HeaderHygieneFeature_CtorNullSequences_Throws_NamingCallerKeyOptions()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => new HeaderHygieneFeature(new CredProxCoreOptions(), null!));

        Assert.Equal("callerKeyOptions", error.ParamName);
    }

    [Fact]
    public async Task HeaderHygieneFeature_Apply_NullContext_Throws_NamingContext()
    {
        var feature = new HeaderHygieneFeature(new CredProxCoreOptions(), []);

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => feature.ApplyAsync(null!, default).AsTask());

        Assert.Equal("context", error.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Pipeline_CtorGuards_EachFeatureSequenceByName(int nullArgument)
    {
        // The three sequences have the same shape; only the paramName separates the
        // documented refusal from the OrderBy accident downstream (M31 :46-:48 triage).
        ArgumentNullException error = nullArgument switch
        {
            0 => Assert.Throws<ArgumentNullException>(
                () => new CredProxPipeline(null!, [], [])),
            1 => Assert.Throws<ArgumentNullException>(
                () => new CredProxPipeline([], null!, [])),
            _ => Assert.Throws<ArgumentNullException>(
                () => new CredProxPipeline([], [], null!)),
        };

        Assert.Equal(
            nullArgument switch { 0 => "requestFeatures", 1 => "pipelineFeatures", _ => "responseFeatures" },
            error.ParamName);
    }
}
