using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The guard's refusal is the operator's only pointer to the public seam that fixes a
/// caller with no way to authenticate, so the text must name a call the operator can
/// compile against: <c>WithCallerAuthenticator&lt;T&gt;()</c> on the builder the entry
/// hands back (0.15 made the old <c>AddCredProxCallerAuthenticator</c> internal).
/// docs/production.md relies on the message existing and naming the registration call.
/// </summary>
public sealed class CallerAuthenticatorStartupGuardTests
{
    [Fact]
    public async Task Refusal_NamesPublicWithCallerAuthenticatorSeam_NotTheInternalCall()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:lonely:Description"] = "a caller with no keys and no authenticator",
            }).Build();
        var services = new ServiceCollection().BuildServiceProvider();
        var guard = new CallerAuthenticatorStartupGuard(services, configuration);

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => guard.StartAsync(CancellationToken.None));

        Assert.Contains("WithCallerAuthenticator<T>()", refusal.Message);
        Assert.DoesNotContain("AddCredProxCallerAuthenticator", refusal.Message);
        Assert.Contains("'lonely'", refusal.Message);
    }
}
