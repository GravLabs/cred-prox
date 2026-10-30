using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The single admission gate (§3.4, M2/M3 review carry): exact ordinal match only — no
/// trimming, no case folding, no normalization — and the rejection message never contains
/// the rejected value.
/// </summary>
public sealed class PartitionSourceBindingTests
{
    private const string Header = "X-Env";

    private static PartitionSourceBinding Binding(params string[] allowed) =>
        new(new HeaderPartitionSource(Header), allowed, "header:X-Env");

    private static HttpContext ContextWith(string? headerValue)
    {
        var context = new DefaultHttpContext();
        if (headerValue is not null)
        {
            context.Request.Headers[Header] = headerValue;
        }

        return context;
    }

    [Fact]
    public async Task ExactAllowedValue_IsAdmitted()
    {
        var partition = await Binding("prod", "staging")
            .ResolveAsync(ContextWith("staging"), default);

        Assert.Equal("staging", partition);
    }

    [Theory]
    [InlineData(null)]                  // header absent
    [InlineData("")]                    // header present but empty
    [InlineData("Prod")]                // case differs
    [InlineData(" prod")]               // leading space
    [InlineData("prod ")]               // trailing space
    [InlineData("prod, staging")]       // joined values
    [InlineData("attacker.com")]        // host-shaped value
    [InlineData("app?evil=1")]          // query separator
    [InlineData("app#frag")]            // fragment separator
    [InlineData("app@evil")]            // userinfo separator
    [InlineData("../evil")]             // traversal
    [InlineData("%2eprod")]             // encoded dot
    [InlineData("prod\r\nX: y")]        // header injection attempt
    [InlineData("prod\nX: y")]          // bare LF
    public async Task AnythingButAnExactAllowedValue_IsRejected(string? value)
    {
        var binding = Binding("prod");

        var error = await Assert.ThrowsAsync<PartitionNotAllowedException>(
            () => binding.ResolveAsync(ContextWith(value), default).AsTask());

        // The message names the source, never the rejected value (§3.4).
        Assert.DoesNotContain("attacker", error.Message);
        Assert.DoesNotContain("evil", error.Message);
        Assert.DoesNotContain("%2e", error.Message);
        Assert.DoesNotContain("\r", error.Message);
    }

    [Fact]
    public void EmptyAllowList_IsRejectedAtConstruction()
    {
        Assert.Throws<ArgumentException>(() =>
            new PartitionSourceBinding(new HeaderPartitionSource(Header), [], "header:X-Env"));
    }

    [Fact]
    public async Task HeaderSource_ReadsFirstValueUntrimmed()
    {
        var context = ContextWith(" prod ");
        var value = await new HeaderPartitionSource(Header).GetPartitionAsync(context, default);

        Assert.Equal(" prod ", value); // trimming would defeat exact matching
    }

    [Fact]
    public async Task HeaderSource_MissingHeader_IsNull()
    {
        Assert.Null(await new HeaderPartitionSource(Header).GetPartitionAsync(new DefaultHttpContext(), default));
    }

    [Fact]
    public void HeaderFactory_CreatesSources_AndSchemeIsHeader()
    {
        var factory = new HeaderPartitionSourceFactory();

        Assert.Equal("header", factory.Scheme);
        Assert.IsType<HeaderPartitionSource>(factory.CreateSource("X-Env"));
        Assert.Throws<ArgumentException>(() => factory.CreateSource(string.Empty));
    }
}
