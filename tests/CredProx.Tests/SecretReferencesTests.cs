using CredProx;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Reference extraction from configuration values: whole-value references and
/// <c>{secret:...}</c> template references, found recursively.
/// </summary>
public sealed class SecretReferencesTests
{
    [Theory]
    [InlineData("secret:contoso-id", new[] { "contoso-id" })]
    [InlineData("plain", new string[0])]
    [InlineData("https://h/t?tid={secret:tid}&u={secret:user}", new[] { "tid", "user" })]
    [InlineData("secret:{partition}-id", new[] { "{partition}-id" })]
    [InlineData(null, new string[0])]
    [InlineData("{secret:a}{secret:b}", new[] { "a", "b" })]
    [InlineData("{secret:}", new string[0])]
    [InlineData("{secret:oops", new string[0])]
    public void FindInValue_FindsBothForms(string? value, string[] expected)
    {
        Assert.Equal(expected, SecretReferences.FindInValue(value));
    }

    [Theory]
    [InlineData(
        "https://signin.{partition}.acme.com/basicauth?tenant_id={secret:acme-{partition}-tenantid}",
        new[] { "acme-{partition}-tenantid" })]
    [InlineData("secret:acme-{partition}-user", new[] { "acme-{partition}-user" })]
    public void FindInValue_FindsDynamicNamesFromTheLoginExchangeExample(string value, string[] expected)
    {
        // §3.2: reference names may themselves contain {partition}; the templated form is
        // matched by brace depth, not a flat pattern.
        Assert.Equal(expected, SecretReferences.FindInValue(value));
    }

    [Fact]
    public void FindInSection_FindsReferencesRecursively()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:contoso:ClientId"] = "secret:contoso-id",
            ["CredProx:Credentials:contoso:Nested:Deep"] = "x{secret:deep-id}y",
            ["CredProx:Credentials:contoso:Container:Plain"] = null,
            ["CredProx:InboundKeyHeader"] = "X-API-Key",
        }).Build();

        var names = SecretReferences.FindInSection(configuration.GetSection("CredProx"));

        Assert.Equal(new[] { "contoso-id", "deep-id" }, names.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void FindInSection_CollectsDynamicNamesFromTheLoginExchangeCredential()
    {
        // The §3.2 login-exchange credential shape: one templated reference whose name contains
        // {partition}, plus two bare dynamic references.
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:acme:LoginEndpoint"] =
                "https://signin.{partition}.acme.com/basicauth?tenant_id={secret:acme-{partition}-tenantid}",
            ["CredProx:Credentials:acme:Basic:User"] = "secret:acme-{partition}-user",
            ["CredProx:Credentials:acme:Basic:Password"] = "secret:acme-{partition}-pass",
        }).Build();

        var names = SecretReferences.FindInSection(configuration.GetSection("CredProx:Credentials:acme"));

        Assert.Equal(
            new[] { "acme-{partition}-pass", "acme-{partition}-tenantid", "acme-{partition}-user" },
            names.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void FindInSection_LeafSectionWithReference_IsIncluded()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CredProx:Cert"] = "secret:cert" })
            .Build();

        Assert.Equal(new[] { "cert" }, SecretReferences.FindInSection(configuration.GetSection("CredProx:Cert")));
    }

    [Fact]
    public void FindInSection_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => SecretReferences.FindInSection(null!));
    }
}
