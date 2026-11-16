using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome B binder rules: TokenClientIds is a known caller key and binds; a caller
/// with no keys but token clients is legal; a caller with neither keeps the ORIGINAL
/// no-usable-key error; the singular typo fails closed and names the real key; and one
/// client id listed by two callers is rejected — the mapper would otherwise pick a
/// caller by registry luck.
/// </summary>
public sealed class CallerTokenConfigTests
{
    private static string Hash() =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("unused"))).ToLowerInvariant();

    private static CallerRegistry Bind(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))).Bind();
    }

    private static OptionsValidationException BindError(Dictionary<string, string?> entries) =>
        Assert.Throws<OptionsValidationException>(() => Bind(entries));

    [Fact]
    public void TokenOnlyCaller_Binds_WithTokenClientIds()
    {
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:TokenClientIds:1"] = "client-def",
        });

        Assert.True(registry.TryGet("agent-1", out var definition));
        Assert.Empty(definition!.Keys);
        Assert.Equal(["client-abc", "client-def"], definition.TokenClientIds);
    }

    [Fact]
    public void KeyedCaller_CanAlsoDeclareTokenClients()
    {
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(),
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
        });

        Assert.True(registry.TryGet("agent-1", out var definition));
        Assert.Single(definition!.Keys);
        Assert.Equal(["client-abc"], definition.TokenClientIds);
    }

    [Fact]
    public void NoKeysAndNoTokenClients_KeepsTheOriginalError()
    {
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Operations:0:Route"] = "acme",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains("The caller 'agent-1' declares no usable key under Keys.", StringComparison.Ordinal));
    }

    [Fact]
    public void KeysEmptyExplicitly_TokenClientsRescueTheBind()
    {
        // An empty Keys section with token clients is a legal token-only caller.
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
        });
        Assert.True(registry.TryGet("agent-1", out var definition));
        Assert.Empty(definition!.Keys);
    }

    [Fact]
    public void SingularTypo_TokenClients_FailsClosedAndNamesTheRealKey()
    {
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(),
            ["CredProx:Callers:agent-1:TokenClients:0"] = "client-abc",
        });

        Assert.Contains(error.Failures, f => f.Contains("TokenClients", StringComparison.Ordinal));
        Assert.Contains(error.Failures, f => f.Contains("TokenClientIds", StringComparison.Ordinal));
    }

    [Fact]
    public void DuplicateClientIdAcrossCallers_Fails()
    {
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "shared-client",
            ["CredProx:Callers:agent-2:TokenClientIds:0"] = "SHARED-CLIENT",
        });

        // Case-insensitive: the mapper matches tokens case-insensitively, so the
        // duplicate check must see these two as the same client id.
        Assert.Contains(
            error.Failures,
            f => f.Contains("is listed by more than one caller", StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyTokenClientEntry_Fails()
    {
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:TokenClientIds:1"] = "",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains("agent-1", StringComparison.Ordinal)
                && f.Contains("TokenClientIds", StringComparison.Ordinal));
    }

    [Fact]
    public void WhitespacePaddedTokenClientEntry_Fails()
    {
        // M39 fold F5: padding must not bind silently — the entry looks right in the
        // config, the mapper matches verbatim, and it admits nobody (the verdict's
        // ' client-sec-c ' probe).
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = " client-abc ",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains("agent-1", StringComparison.Ordinal)
                && f.Contains("whitespace", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void WhitespacePaddedOperationName_Fails_NamingCallerAndRuleIndex()
    {
        // M39 fold 2 (verdict C F1): the padded-entry family applies to rule Names too —
        // scope matching is ordinal, so " Read " can never intersect the role "Read".
        // The rule would lock out every request that needs it, with no startup refusal.
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:Operations:0:Route"] = "reports",
            ["CredProx:Callers:agent-1:Operations:0:Paths:0"] = "/reports/*",
            ["CredProx:Callers:agent-1:Operations:0:Name"] = " Read ",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains("agent-1", StringComparison.Ordinal)
                && f.Contains("Operations:0", StringComparison.Ordinal)
                && f.Contains("whitespace", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DuplicateClientIdInsideOneCaller_NamesItAsTwiceListed()
    {
        // M39 fold F6: a case-variant pair inside ONE caller is its own defect; the
        // two-owner wording names the same caller twice and hides it.
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:TokenClientIds:1"] = "CLIENT-ABC",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains("is listed twice by caller 'agent-1'", StringComparison.Ordinal));
    }

    [Fact]
    public void DefinitionWithoutTokenClients_YieldsEmptyList()
    {
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(),
        });

        Assert.True(registry.TryGet("agent-1", out var definition));
        Assert.Empty(definition!.TokenClientIds);
    }
}
