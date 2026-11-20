using System.Net;
using System.Net.Http.Headers;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The scrubber still passes bodies it cannot open straight through — what changed
/// (M45 security finding F-3) is that the operator hears about the class of response,
/// once per route and shape, so a vendor echoing through an unopenable body is visible
/// instead of silently inert. The warning names the class, never the body.
/// </summary>
public sealed class ScrubPassThroughWarningTests
{
    private const string Secret = "SUPERVENDORCRED123";

    private static (ResponseScrubFeature Feature, Capturing Capturing) Feature()
    {
        var capturing = new Capturing();
        return (new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = true }, capturing), capturing);
    }

    private static HttpResponseMessage Body(string? mediaTypeOrNull, string body)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        if (mediaTypeOrNull is null)
        {
            response.Content.Headers.ContentType = null;
        }
        else
        {
            response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(mediaTypeOrNull);
        }

        return response;
    }

    private static DefaultHttpContext Context(HttpResponseMessage response, string? destination = null)
    {
        var context = new DefaultHttpContext();
        var state = new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
        {
            ProxyResponse = response,
        };
        if (destination is not null)
        {
            state.Destination = new DestinationEntry(destination, new DestinationDefinition(), null);
        }

        context.Features.Set(state);
        CredProxInjectedSecrets.GetOrCreate(context).Register(Secret);
        return context;
    }

    [Fact]
    public async Task OctetEcho_WarnsOnce_NamingTheClass_BodyStillPassesThroughByteIdentical()
    {
        var (feature, logs) = Feature();
        var echo = $"echo:{Secret}";
        var response = Body("application/octet-stream", echo);

        await feature.ApplyAsync(Context(response), CancellationToken.None);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("application/octet-stream", warning.Message, StringComparison.Ordinal);
        Assert.Contains("forwarded untouched", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, warning.Message, StringComparison.Ordinal);
        Assert.Equal(echo, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task MissingMediaType_WarnsOnce_NamingTheMissingType()
    {
        var (feature, logs) = Feature();

        await feature.ApplyAsync(Context(Body(null, $"echo:{Secret}")), CancellationToken.None);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("no media type", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SameRouteAndShape_WarnsOnlyOnce()
    {
        var (feature, logs) = Feature();

        await feature.ApplyAsync(Context(Body("application/octet-stream", $"echo:{Secret}")), CancellationToken.None);
        await feature.ApplyAsync(Context(Body("application/octet-stream", $"echo:{Secret}")), CancellationToken.None);

        Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task DifferentRoutes_EachWarn()
    {
        var (feature, logs) = Feature();

        await feature.ApplyAsync(
            Context(Body("application/octet-stream", $"echo:{Secret}"), destination: "graph"),
            CancellationToken.None);
        await feature.ApplyAsync(
            Context(Body("application/octet-stream", $"echo:{Secret}"), destination: "storage"),
            CancellationToken.None);

        Assert.Equal(2, logs.Entries.Count(e => e.Level == LogLevel.Warning));
    }

    [Fact]
    public async Task TextBody_Inspected_NoUninspectedWarning()
    {
        var (feature, logs) = Feature();
        var context = Context(Body("text/plain", $"echo:{Secret}"));

        await feature.ApplyAsync(context, CancellationToken.None);

        Assert.DoesNotContain(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal(
            "echo:[redacted]",
            await context.Features.Get<CredProxRequestState>()!.ProxyResponse!.Content!.ReadAsStringAsync());
    }

    [Fact]
    public async Task ScrubbingDisabled_SaysNothing()
    {
        var logs = new Capturing();
        var feature = new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = false }, logs);

        await feature.ApplyAsync(Context(Body("application/octet-stream", $"echo:{Secret}")), CancellationToken.None);

        Assert.Empty(logs.Entries);
    }

    /// <summary>Minimal <see cref="ILogger{TCategoryName}"/> capture for a concrete
    /// feature constructor argument.</summary>
    private sealed class Capturing : ILogger<ResponseScrubFeature>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
            {
                Entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
