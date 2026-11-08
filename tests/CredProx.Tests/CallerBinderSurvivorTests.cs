using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="CallerBinder"/>: the rebind null guard, the
/// duplicate-KeyId short-circuit (one error per defect, never a cascade), the
/// non-negative budget boundary (zero is legal), and the unknown-key guidance tail
/// that explains why an unknown key is a hazard, not a typo.
/// </summary>
public sealed class CallerBinderSurvivorTests
{
    private static CallerBinder Binder(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)));
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();

    [Fact]
    public void Rebind_NullPrevious_Throws()
    {
        // The provider always passes the live registry; the guard is the public contract
        // (callers are plain data but the parameter is non-nullable).
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
        });

        Assert.Throws<ArgumentNullException>(() => binder.Rebind(null!));
    }

    [Fact]
    public void DuplicateKeyId_SecondKeyAlsoMissingHash_ReportsOnlyTheDuplicate()
    {
        // The duplicate check short-circuits the rest of the key's validation: one defect,
        // one error. Dropping the short-circuit would cascade a second 'no KeyHash' error
        // for a key the operator is already being told to remove.
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:1:KeyId"] = "k1",
        }).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("declares the KeyId 'k1' twice", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Limits_PermitsPerIntervalZero_BindsAsUnlimitedBudget()
    {
        // "must be a non-negative integer" — zero is in range (pointless but legal).
        var registry = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "0",
        }).Bind();

        Assert.Equal(0, registry.Get("app-a").Limits!.PermitsPerInterval);
    }

    [Fact]
    public void UnknownKey_ErrorCarriesTheWeakenGuidanceTail()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limit:PermitsPerInterval"] = "5",
        }).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("Known keys at that level: Keys, Limits, Operations.", failure, StringComparison.Ordinal);
        Assert.EndsWith(
            "silently weaken the caller's allow-list — fix the spelling or remove the key.",
            failure,
            StringComparison.Ordinal);
    }
}
