using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Binder rules for <c>TokenClientIds</c>: the key is known and accepted; a caller with
/// no keys but token clients is legal (its credential is the token path the add-on
/// registers); a caller with neither keeps the no-usable-key error; the singular typo
/// fails closed and names the real key. The entry VALUES are validated by the add-on's
/// registration — see <see cref="CallerTokenRegistrationValidationTests"/>.
/// </summary>
public sealed class CallerTokenConfigTests
{
    private static string Hash() =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("unused"))).ToLowerInvariant();

    private static CallerRegistry Bind(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var secretSource = new ConfigurationSecretSource(config);
        // The keys half of the "usable key or token clients" alternative is contributed
        // by the CredProx.CallerKeys rules, as a keys-consuming host would register them.
        return new CallerBinder(
            config,
            new SecretAccessorFactory(secretSource),
            [new CallerKeyRules()]).Bind();
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

        Assert.True(registry.TryGet("agent-1", out _));
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

        Assert.True(registry.TryGet("agent-1", out _));
    }

    [Fact]
    public void NoKeysAndNoTokenClients_Refused_NamingBothPaths()
    {
        var error = BindError(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Operations:0:Route"] = "acme",
        });

        Assert.Contains(
            error.Failures,
            f => f.Contains(
                "The caller 'agent-1' declares no usable key under Keys and declares no TokenClientIds.",
                StringComparison.Ordinal));
    }

    [Fact]
    public void KeysEmptyExplicitly_TokenClientsRescueTheBind()
    {
        // An empty Keys section with token clients is a legal token-only caller.
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
        });
        Assert.True(registry.TryGet("agent-1", out _));
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
    public void KeysOnlyCaller_Binds_WithoutAnyTokenKey()
    {
        var registry = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(),
        });

        Assert.True(registry.TryGet("agent-1", out _));
    }
}
