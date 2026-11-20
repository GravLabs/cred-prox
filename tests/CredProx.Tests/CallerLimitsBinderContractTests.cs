using System.Security.Cryptography;
using System.Text;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M48 watch-list action for <see cref="CallerLimits"/> and <see cref="CallerClusterLimits"/>:
/// the budget knobs were covered through config paths, but nothing named these two types, which
/// freeze public in 1.0. Direct binder-level cells pin their shipped contract: the type defaults
/// (0 permits = budget off; the 1-minute window; null cluster members inherit), case-insensitive
/// cluster keys, the interval-only override shape, and the strict parse rules that refuse signed,
/// fractional or non-positive values instead of silently widening a caller's budget (§3.7).
/// </summary>
public sealed class CallerLimitsBinderContractTests
{
    [Fact]
    public void CallerLimits_TypeDefaults_BudgetOff_OneMinuteWindow()
    {
        var limits = new CallerLimits();

        Assert.Equal(0, limits.PermitsPerInterval);
        Assert.Equal(TimeSpan.FromMinutes(1), limits.Interval);
    }

    [Fact]
    public void CallerClusterLimits_TypeDefaults_AllNull_ThereforeInherit()
    {
        var cluster = new CallerClusterLimits();

        Assert.Null(cluster.PermitsPerInterval);
        Assert.Null(cluster.Interval);
    }

    [Fact]
    public void Clusters_Key_IsCaseInsensitive_AtTypeAndThroughTheBinder()
    {
        var limits = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "100",
            // Declared with capitals, looked up with lowercase, as YARP cluster ids vary.
            ["CredProx:Callers:app-a:Limits:Clusters:OpenAI:Interval"] = "00:00:10",
        }).Bind().Get("app-a").Limits!;

        Assert.True(limits.Clusters.TryGetValue("openai", out var cluster));
        Assert.Equal(TimeSpan.FromSeconds(10), cluster!.Interval);
        Assert.Null(cluster.PermitsPerInterval);
        Assert.Equal(100, limits.PermitsPerInterval);
    }

    [Fact]
    public void PermitsSetWithoutInterval_WindowStaysTheTypeDefaultOneMinute()
    {
        var limits = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "10",
        }).Bind().Get("app-a").Limits!;

        Assert.Equal(10, limits.PermitsPerInterval);
        Assert.Equal(TimeSpan.FromMinutes(1), limits.Interval);
    }

    [Fact]
    public void ClusterPermitsZero_IsTheDisabledSentinel_NotAnError()
    {
        var limits = Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "100",
            ["CredProx:Callers:app-a:Limits:Clusters:quiet:PermitsPerInterval"] = "0",
        }).Bind().Get("app-a").Limits!;

        Assert.Equal(0, limits.Clusters["quiet"].PermitsPerInterval);
    }

    [Theory]
    [InlineData("+5")]
    [InlineData("5.0")]
    [InlineData("1e2")]
    public void PermitsMustBePlainNonNegativeInteger_Fails(string permits)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = permits,
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains(
            $"PermitsPerInterval '{permits}', which must be a non-negative integer", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    [InlineData("soon")]
    public void ClusterIntervalMustBePositive_Fails_NamingTheClusterPath(string interval)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("v1"),
            ["CredProx:Callers:app-a:Limits:Clusters:c1:Interval"] = interval,
        }).Bind());

        Assert.Contains(ex.Failures, f => f.Contains(
            $"Limits:Clusters:c1:Interval '{interval}', which must be a positive TimeSpan", StringComparison.Ordinal));
    }

    private static CallerBinder Bind(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            [new CallerKeyRules()]);
    }

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
