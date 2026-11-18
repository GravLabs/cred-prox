using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Entry-shape rules for <c>CredProx:Callers:&lt;id&gt;:Keys</c> live with the keys' owner
/// (<c>CallerKeyRules</c> in CredProx.CallerKeys): a key needs a unique <c>KeyId</c> and a
/// <c>KeyHash</c> that is a <c>sha256:&lt;64 hex&gt;</c> value or a <c>secret:</c>
/// reference resolving to one, and an <c>ExpiresAt</c> that parses. Unknown keys under a
/// <c>Keys</c> entry fail closed (M14a). A caller needs at least one authentication path —
/// a usable key here or <c>TokenClientIds</c> — and the missing-path error is emitted only
/// when nothing else already named the caller's key trouble. The core runs these rules at
/// host start and on every live rebind; the live cells for that channel are in
/// <see cref="CallerRebindSurvivorTests"/>. This file pins the rule itself: the refusals
/// it returns and the exact wording an operator reads — errors name the caller and key id,
/// never a key value or hash.
/// </summary>
public sealed class CallerKeyRulesTests
{
    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static IReadOnlyList<string> RuleErrors(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var callers = config.GetSection("CredProx:Callers").GetChildren()
            .Select(section => new CallerRegistryEntry(section.Key, section))
            .ToList();
        return new CallerKeyRules()
            .Validate(callers);
    }

    [Fact]
    public void CleanKey_RulePasses_WithEveryField()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] = "2027-01-01T00:00:00+00:00",
        });

        Assert.Empty(errors);
    }

    [Fact]
    public void MissingKeyId_Refuses_Verbatim()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
        });

        Assert.Contains("The caller 'app-a' has a key with no KeyId.", errors);
    }

    [Fact]
    public void DuplicateKeyId_Refuses_Verbatim_AndReportsOnlyTheDuplicate()
    {
        // The duplicate check short-circuits the rest of the key's validation: one defect,
        // one error — no cascading 'no KeyHash' for the key being told to go.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:1:KeyId"] = "k1",
        });

        var failure = Assert.Single(errors);
        Assert.Contains("The caller 'app-a' declares the KeyId 'k1' twice.", failure);
    }

    [Fact]
    public void MissingKeyHash_Refuses_Verbatim()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        });

        Assert.Contains("The caller 'app-a' key 'k1' has no KeyHash.", errors);
    }

    [Fact]
    public void MalformedKeyHash_Refuses_Verbatim_NeverTheValue()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "plaintext-secret-value",
        });

        Assert.Contains(
            "The caller 'app-a' key 'k1' has a KeyHash that is not 'sha256:<64 hex digits>'.",
            errors);
        Assert.DoesNotContain(errors, e => e.Contains("plaintext-secret-value", StringComparison.Ordinal));
    }

    [Fact]
    public void UnparseableExpiresAt_Refuses_Verbatim()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] = "next tuesday",
        });

        Assert.Contains(
            "The caller 'app-a' key 'k1' has an ExpiresAt that is not a date-time.",
            errors);
    }

    [Fact]
    public void UnknownKeyUnderKeyEntry_Refuses_NamingThePathAndKnownSetInOrdinalOrder()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:Hash"] = Hash("v1"),
        });

        // Two arms fire on this input: the unknown key fails closed (M14a) and the entry
        // then genuinely has no KeyHash — both are stated, neither cancels the other.
        Assert.Contains(errors, e => e.Contains("Keys:0:Hash", StringComparison.Ordinal));
        Assert.Contains(
            errors,
            // Ordinal puts KeyHash before KeyId ('H' < 'I') — the exact operator-facing order.
            e => e.Contains("Known keys at that level: ExpiresAt, KeyHash, KeyId.", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("The caller 'app-a' key 'k1' has no KeyHash.", StringComparison.Ordinal));
    }

    [Fact]
    public void UnresolvableSecretRef_AcceptedUnseen_TheSoleResolverRefuses()
    {
        // Shape-only: telling a resolvable reference from a missing one would need a
        // resolution, and exactly one resolution per declared secret per bind is the
        // rule — the eager table contributor is the sole resolver and refuses the bind
        // there (CallerKeysEagerTableTests.
        // TableBuild_WhenASecretFailsToResolve_RefusesNamingCallerAndKey pins that).
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "secret:missing-hash",
        });

        Assert.Empty(errors);
    }

    [Fact]
    public void EmptySecretRef_Refuses_Verbatim()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "secret:",
        });

        Assert.Contains("The caller 'app-a' key 'k1' has an empty secret reference as its KeyHash.", errors);
    }

    [Fact]
    public void LiteralNonHashKeyHash_Refuses_WithoutNamingTheValue()
    {
        // A literal that is not a hash is refused by shape only — what it looks like
        // must not reach the error text; the secret case (a reference resolving to
        // non-hash text) is refused by the sole resolver, pinned in the eager-table
        // tests, and there too the value never enters the message.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "hunter2",
        });

        Assert.Contains(
            "The caller 'app-a' key 'k1' has a KeyHash that is not 'sha256:<64 hex digits>'.",
            errors);
        Assert.DoesNotContain(errors, e => e.Contains("hunter2", StringComparison.Ordinal));
    }

    [Fact]
    public void NoUsableKeyNoTokenClients_Refuses_NamingBothPaths()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/x",
        });

        Assert.Contains(
            "The caller 'app-a' declares no usable key under Keys and declares no TokenClientIds.",
            errors);
    }

    [Fact]
    public void TokenClientsRescueTheCaller_WithoutAnyKey()
    {
        // The token path is the alternative authentication path CredProx.CallerTokens
        // registers; this package must refuse only when neither path is declared.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
        });

        Assert.Empty(errors);
    }

    [Fact]
    public void OtherKeyError_SuppressesTheMissingPathError_OneDefectOneError()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        });

        Assert.Contains("The caller 'app-a' key 'k1' has no KeyHash.", errors);
        Assert.DoesNotContain(
            errors,
            e => e.Contains("declares no usable key", StringComparison.Ordinal));
    }

    // "sha256:" + exactly 64 hex digits is the whole format; each rejection arm breaks
    // exactly one clause (length, prefix, hex bytes), never two at once.
    [Theory]
    [InlineData("sha256:a")]                                       // short
    [InlineData("sha256:" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "a")] // 65 chars
    [InlineData("md5:" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef")] // wrong prefix, 64 hex
    [InlineData("sha256:zz" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcd")] // 64 chars, non-hex
    public void TryParseHash_Rejects_MalformedValues(string value)
    {
        Assert.False(CallerKeyRules.TryParseHash(value, out var hash));
        Assert.Empty(hash);
    }

    [Theory]
    [InlineData("sha256:" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef")]
    [InlineData("SHA256:" + "0123456789ABCDEF" + "0123456789ABCDEF" + "0123456789ABCDEF" + "0123456789ABCDEF")]
    public void TryParseHash_Accepts_CaseInsensitiveHex(string value)
    {
        Assert.True(CallerKeyRules.TryParseHash(value, out var hash));
        Assert.Equal(32, hash.Length);
    }
}
