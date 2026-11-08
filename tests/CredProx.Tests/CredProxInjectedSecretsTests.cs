using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="CredProxInjectedSecrets">: the per-request
/// record must actually live in the feature collection — the attach path and the
/// scrub path meet here through two separate <see cref="CredProxInjectedSecrets.GetOrCreate"/>
/// calls, and a record that is created but never published silently un-scrubs
/// every reflected credential.
/// </summary>
public sealed class CredProxInjectedSecretsTests
{
    [Fact]
    public void GetOrCreate_PublishesIntoFeatures_SameInstanceEveryCall()
    {
        var context = new DefaultHttpContext();

        var first = CredProxInjectedSecrets.GetOrCreate(context);
        first.Register("tok-abc");
        var second = CredProxInjectedSecrets.GetOrCreate(context);

        Assert.Same(first, second);
        Assert.True(second.HasAny); // the attach-side registration is visible scrub-side
        Assert.Equal(["tok-abc"], second.Values);
    }

    [Fact]
    public void GetOrCreate_NullContext_Throws_NamingContext()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => CredProxInjectedSecrets.GetOrCreate(null!));

        Assert.Equal("context", ex.ParamName);
    }

    [Fact]
    public void Register_EmptyOrNull_RegistersNothing()
    {
        var secrets = new CredProxInjectedSecrets();

        secrets.Register(null!);
        secrets.Register("");

        Assert.False(secrets.HasAny);
        Assert.Empty(secrets.Values);
    }

    [Fact]
    public void Register_RegistersRawAndEncodedForm_EachOnce()
    {
        var secrets = new CredProxInjectedSecrets();

        secrets.Register("a b&c");
        secrets.Register("a b&c"); // duplicate: raw and encoded both deduped

        Assert.Equal(["a b&c", "a%20b%26c"], secrets.Values);
    }

    [Fact]
    public void Register_ValueWithoutEncodingOnlyRegistersRaw()
    {
        var secrets = new CredProxInjectedSecrets();

        secrets.Register("plain-token_1");

        Assert.Equal(["plain-token_1"], secrets.Values);
    }
}
