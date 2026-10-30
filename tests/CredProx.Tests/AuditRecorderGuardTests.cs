using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M7 review note (d), carried into M8 because the resilience retry makes transform
/// re-runs reachable: <see cref="CredProxAuditRecorder.Begin"/> on a context that is
/// already observing must not double-wrap the response body or schedule a second record.
/// </summary>
public sealed class AuditRecorderGuardTests
{
    private sealed class CapturingSink : IAuditSink
    {
        public List<(string Event, IReadOnlyDictionary<string, object?> Fields)> Records { get; } = [];

        public ValueTask WriteAsync(
            string eventName,
            IReadOnlyDictionary<string, object?> fields,
            CancellationToken cancellationToken)
        {
            Records.Add((eventName, fields));
            return ValueTask.CompletedTask;
        }
    }

    private static CredProxAuditRecorder CreateRecorder(CapturingSink sink, bool enabled = true) =>
        new(
            [sink],
            new CredProxAuditOptions { Enabled = enabled },
            TimeProvider.System,
            NullLogger<CredProxAuditRecorder>.Instance,
            new CredProxCoreOptions(),
            callerKeyOptions: null);

    [Fact]
    public async Task DoubleBegin_WrapsOnceAndCountsBytesOnce()
    {
        var sink = new CapturingSink();
        var recorder = CreateRecorder(sink);
        var context = new DefaultHttpContext();
        var body = new MemoryStream();
        context.Response.Body = body;

        recorder.Begin(context);
        var wrapped = context.Response.Body;
        Assert.IsType<CountingResponseBodyStream>(wrapped);

        recorder.Begin(context); // the guard: already wrapped, nothing to do — no re-wrap, no second record scheduled
        Assert.Same(wrapped, context.Response.Body);

        await context.Response.WriteAsync("hello");
        await context.Response.CompleteAsync();

        Assert.Equal(5, ((CountingResponseBodyStream)wrapped).BytesWritten);
        Assert.Equal("hello"u8.Length, body.Length); // the body passed through exactly once
    }

    [Fact]
    public async Task SingleBegin_RecordsOnCompletion()
    {
        var sink = new CapturingSink();
        var recorder = CreateRecorder(sink);
        var context = new DefaultHttpContext();
        var body = new MemoryStream();
        context.Response.Body = body;

        recorder.Begin(context);
        await context.Response.WriteAsync("x");
        await context.Response.CompleteAsync();

        // DefaultHttpContext's swapped-in body feature does not run OnCompleted callbacks,
        // so the record itself is asserted end-to-end in AuditIntegrationTests; here the
        // wrap is what the guard governs.
        Assert.Equal(1, ((CountingResponseBodyStream)context.Response.Body).BytesWritten);
        Assert.Single(body.ToArray());
    }

    [Fact]
    public void Disabled_LeavesBodyUntouched()
    {
        var sink = new CapturingSink();
        var recorder = CreateRecorder(sink, enabled: false);
        var context = new DefaultHttpContext();
        var body = new MemoryStream();
        context.Response.Body = body;

        recorder.Begin(context);

        Assert.Same(body, context.Response.Body);
    }
}
