using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// House shape of the §8.3 consent signal: a sealed, state-only exception — the authorize
/// URL is mandatory (a consent problem without an entry point is still returned, but a
/// provider that signals consent must name where consent happens), and the message is the
/// developer-facing one that never reaches the response body (§3.4).
/// </summary>
public class ConsentRequiredExceptionTests
{
    [Fact]
    public void Ctor_KeepsAuthorizeUrlAndMessage()
    {
        var ex = new ConsentRequiredException("https://id.example/authorize?x=1", "contoso needs consent");

        Assert.Equal("https://id.example/authorize?x=1", ex.AuthorizeUrl);
        Assert.Equal("contoso needs consent", ex.Message);
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Ctor_RejectsMissingAuthorizeUrl(string? authorizeUrl)
    {
        // ThrowIfNullOrEmpty: ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(
            () => new ConsentRequiredException(authorizeUrl!, "consent"));
    }
}
