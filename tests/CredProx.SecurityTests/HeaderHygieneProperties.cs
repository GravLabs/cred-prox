using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §5.2 "Header hygiene" as a property: whatever the caller sends in the key header —
/// any generated value, including ones that would break naive header handling — it never
/// survives into the outbound request, and stripping it never takes anything else with it.
/// </summary>
public sealed class HeaderHygieneProperties
{
    [Property(MaxTest = 500)]
    public async Task CallerKey_NeverReachesTheUpstream(NonNull<string> generated)
    {
        var context = SecurityContexts.Create(out var proxyRequest, destinationName: null);
        proxyRequest.Headers.TryAddWithoutValidation("X-API-Key", generated.Get);
        proxyRequest.Headers.TryAddWithoutValidation("X-Trace", "keep-me");

        await new HeaderHygieneFeature(new CredProxCoreOptions(), []).ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-API-Key"));
        Assert.True(proxyRequest.Headers.Contains("X-Trace")); // only the key header goes
    }

    [Property(MaxTest = 500)]
    public async Task CustomKeyHeader_IsTheOnlyOneStripped(NonNull<string> generated)
    {
        var options = new CredProxCoreOptions { InboundKeyHeader = "X-Custom-Key" };
        var context = SecurityContexts.Create(out var proxyRequest, destinationName: null);
        proxyRequest.Headers.TryAddWithoutValidation("X-Custom-Key", generated.Get);
        proxyRequest.Headers.TryAddWithoutValidation("X-API-Key", "kept-because-not-the-key");

        await new HeaderHygieneFeature(options, []).ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-Custom-Key"));
        Assert.True(proxyRequest.Headers.Contains("X-API-Key"));
    }

    [Fact]
    public async Task DisabledKeyHeader_StripsNothing()
    {
        var context = SecurityContexts.Create(out var proxyRequest, destinationName: null);
        proxyRequest.Headers.TryAddWithoutValidation("X-API-Key", "caller-key");

        await new HeaderHygieneFeature(new CredProxCoreOptions { InboundKeyHeader = "" }, [])
            .ApplyAsync(context, default);

        Assert.True(proxyRequest.Headers.Contains("X-API-Key"));
    }
}
