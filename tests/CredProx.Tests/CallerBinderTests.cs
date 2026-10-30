using System.Security.Cryptography;
using System.Text;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Startup binding of <c>CredProx:Callers</c> (§4 Phase B): every validation error names
/// the caller and key id but never a key value or hash; a <c>secret:</c> hash reference
/// resolves through the caller's own scoped accessor; reloads may empty the registry
/// (kill switch) while startup may not.
/// </summary>
public sealed class CallerBinderTests
{
    [Fact]
    public void BindsCallersKeysAndOperations()
    {
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] = "2027-01-01T00:00:00+00:00",
            ["CredProx:Callers:app-a:Operations:0:Route"] = "reports",
            ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "GET",
            ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/reports/*",
        });

        var registry = binder.Bind();

        var caller = registry.Get("app-a");
        var key = Assert.Single(caller.Keys);
        Assert.Equal("k1", key.KeyId);
        Assert.Equal(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero), key.ExpiresAt);
        var rule = Assert.Single(caller.Operations);
        Assert.Equal("reports", rule.Route);
        Assert.Contains("GET", rule.Methods);
        Assert.Equal("/reports/*", Assert.Single(rule.PathPatterns));
    }

    [Fact]
    public void NoCallersAtStartup_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder([]).Bind());
        Assert.Contains(ex.Failures, f => f.Contains("no caller is configured", StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyRegistryAtReload_IsAllowed()
    {
        // Kill switch: removing every caller is a deliberate reload, not a startup state.
        var binder = Binder([]);
        var empty = binder.Rebind(new CallerRegistry(new Dictionary<string, CallerDefinition>()));
        Assert.Equal(0, empty.Count);
    }

    [Fact]
    public void MissingKeyId_Fails_NamingCaller()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("app-a", StringComparison.Ordinal) && f.Contains("KeyId", StringComparison.Ordinal));
    }

    [Fact]
    public void DuplicateKeyId_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:1:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:1:KeyHash"] = Hash("v2"),
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("twice", StringComparison.Ordinal));
    }

    [Fact]
    public void MalformedHash_Fails_NamingCallerAndKey_NotTheValue()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "plaintext-secret-value",
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("app-a", StringComparison.Ordinal) && f.Contains("k1", StringComparison.Ordinal));
        Assert.DoesNotContain(ex.Failures, f => f.Contains("plaintext-secret-value", StringComparison.Ordinal));
    }

    [Fact]
    public void SecretHashReference_ResolvesThroughCallersScopedAccessor()
    {
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "secret:app-a-key-hash",
            ["CredProx:Secrets:app-a-key-hash"] = Hash("v1"),
        });

        var registry = binder.Bind();
        Assert.Equal(32, Assert.Single(registry.Get("app-a").Keys).Hash.Length);
    }

    [Fact]
    public void SecretHashReference_Unresolvable_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "secret:missing-hash",
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("app-a", StringComparison.Ordinal) && f.Contains("k1", StringComparison.Ordinal));
    }

    [Fact]
    public void CallerWithNoUsableKey_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/x",
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("no usable key", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("reports/*")]      // no leading slash
    [InlineData("/a/**/b")]        // ** not trailing
    [InlineData("/a/x*y")]         // partial wildcard
    [InlineData("/a/?b")]          // single-char wildcard not offered
    public void InvalidPathPattern_Fails_NamingCaller(string pattern)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Operations:0:Paths:0"] = pattern,
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("app-a", StringComparison.Ordinal) && f.Contains(pattern, StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyMethodEntry_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "",
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("empty Methods entry", StringComparison.Ordinal));
    }

    [Fact]
    public void UnparseableExpiry_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] = "next tuesday",
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("not a date-time", StringComparison.Ordinal));
    }

    // M14a: an unknown key under a caller is a typo, and a typo in an allow-list entry
    // must fail closed — silently ignoring it admits the caller to everything.

    [Fact]
    public void PathPatternsTypo_Fails_NamingCallerAndKey()
    {
        // The exact M13 finding: "PathPatterns" for "Paths" used to be ignored, which
        // admitted the caller to every route. It must now refuse startup.
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Operations:0:Route"] = "files",
            ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "POST",
            ["CredProx:Callers:app-a:Operations:0:PathPatterns:0"] = "/files/**",
        }).Bind());

        Assert.Contains(ex.Failures, f =>
            f.Contains("app-a", StringComparison.Ordinal)
            && f.Contains("Operations:0:PathPatterns", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownKeyAtCallerLevel_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Operation:0:Route"] = "reports",
        }).Bind());

        Assert.Contains(ex.Failures, f =>
            f.Contains("app-a", StringComparison.Ordinal)
            && f.Contains("'Operation'", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownKeyUnderKeyEntry_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:Hash"] = Hash("v1"),
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("Keys:0:Hash", StringComparison.Ordinal));
    }

    [Fact]
    public void KnownKeysInAnyCase_Bind()
    {
        // Config keys are case-insensitive; the known-key check must be too.
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:keys:0:keyid"] = "k1",
            ["CredProx:Callers:app-a:keys:0:keyhash"] = Hash("v1"),
            ["CredProx:Callers:app-a:operations:0:route"] = "reports",
            ["CredProx:Callers:app-a:operations:0:methods:0"] = "GET",
        });

        var registry = binder.Bind();
        Assert.Equal("k1", Assert.Single(registry.Get("app-a").Keys).KeyId);
    }

    [Fact]
    public void UnknownKeyAtReload_Fails()
    {
        // Reloads fail closed too; the provider keeps the previous registry serving.
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Keys:0:Expires"] = "2027-01-01T00:00:00+00:00",
        });

        Assert.Throws<OptionsValidationException>(() =>
            binder.Rebind(new CallerRegistry(new Dictionary<string, CallerDefinition>())));
    }

    [Fact]
    public void Limits_BindsFully()
    {
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "100",
            ["CredProx:Callers:app-a:Limits:Interval"] = "00:01:00",
            ["CredProx:Callers:app-a:Limits:Clusters:openai:PermitsPerInterval"] = "10",
            ["CredProx:Callers:app-a:Limits:Clusters:openai:Interval"] = "00:00:10",
            ["CredProx:Callers:app-a:Limits:Clusters:anthropic:PermitsPerInterval"] = "0",
        });

        var limits = binder.Bind().Get("app-a").Limits!;
        Assert.Equal(100, limits.PermitsPerInterval);
        Assert.Equal(TimeSpan.FromMinutes(1), limits.Interval);
        Assert.Equal(10, limits.Clusters["openai"].PermitsPerInterval);
        Assert.Equal(TimeSpan.FromSeconds(10), limits.Clusters["openai"].Interval);
        Assert.Equal(0, limits.Clusters["anthropic"].PermitsPerInterval);
        Assert.Null(limits.Clusters["anthropic"].Interval);
    }

    [Fact]
    public void Limits_Absent_IsUnlimited()
    {
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
        });

        Assert.Null(binder.Bind().Get("app-a").Limits);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("many")]
    public void Limits_NegativeOrMalformedPermits_Fails(string permits)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = permits,
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("Limits:PermitsPerInterval", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("soon")]
    public void Limits_NonPositiveOrMalformedInterval_Fails(string interval)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "10",
            ["CredProx:Callers:app-a:Limits:Interval"] = interval,
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains("Limits:Interval", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownKeyUnderLimits_Fails_NotSilentlyUnlimited()
    {
        // The M14a fail-open class, budget edition: "Permits" instead of
        // "PermitsPerInterval" must fail closed, never run the caller unlimited (§3.7).
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:Permits"] = "10",
        }).Bind());

        Assert.Contains(ex.Failures, f =>
            f.Contains("Limits:Permits", StringComparison.Ordinal)
            && f.Contains("unknown configuration key", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownKeyUnderLimitsClusters_Fails()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:Clusters:openai:Permit"] = "10",
        }).Bind());

        Assert.Contains(ex.Failures, f =>
            f.Contains("Limits:Clusters:openai:Permit", StringComparison.Ordinal));
    }

    [Fact]
    public void LimitsAtReload_FailsClosed_KeepsPreviousRegistry()
    {
        var binder = Binder(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "-5",
        });

        Assert.Throws<OptionsValidationException>(() =>
            binder.Rebind(new CallerRegistry(new Dictionary<string, CallerDefinition>())));
    }

    private static CallerBinder Binder(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)));
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();
}
