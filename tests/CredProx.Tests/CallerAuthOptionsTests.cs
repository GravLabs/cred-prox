using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// <c>CredProx:CallerAuth</c> binding (M14a): an unknown key here must fail closed at
/// registration. A typo (e.g. <c>Header</c> for <c>HeaderName</c>) would otherwise leave
/// the default header configured while the host believes it set another — header hygiene
/// would strip the wrong header and the caller key could reach the upstream.
/// </summary>
public sealed class CallerAuthOptionsTests
{
    [Fact]
    public void UnknownKey_FailsRegistration_NamingTheKey()
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:CallerAuth:Header"] = "X-App-Key",
        }).Build();

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("'Header'", StringComparison.Ordinal));
    }

    [Fact]
    public void NestedHeaderName_FailsRegistration()
    {
        // CallerAuth:HeaderName:Foo would bind HeaderName to null and silently keep the
        // default header - the same leak shape as a typo, so it must refuse too.
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:CallerAuth:HeaderName:Foo"] = "X-App-Key",
        }).Build();

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("scalar", StringComparison.Ordinal));
    }

    [Fact]
    public void KnownKey_AnyCase_Registers()
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:CallerAuth:headername"] = "X-App-Key",
        }).Build();

        services.AddCredProxCallerAuthentication(config);

        var options = services.BuildServiceProvider().GetRequiredService<CallerKeyOptions>();
        Assert.Equal("X-App-Key", options.HeaderName);
    }

    [Fact]
    public void EmptySection_RegistersWithDefaults()
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().AddInMemoryCollection([]).Build();

        services.AddCredProxCallerAuthentication(config);

        var options = services.BuildServiceProvider().GetRequiredService<CallerKeyOptions>();
        Assert.Equal("X-CredProx-Key", options.HeaderName);
    }
}
