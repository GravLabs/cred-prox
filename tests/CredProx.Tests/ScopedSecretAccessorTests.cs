using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §3.5 rule 4 / §5.2 "Plugin model" row: a plugin's <see cref="ISecretAccessor"/> cannot
/// resolve secrets outside its own config, and errors name the reference, never a value.
/// </summary>
public sealed class ScopedSecretAccessorTests
{
    private const string OwnValue = "super-secret-value";
    private const string OtherValue = "other-secret-value";

    [Theory]
    [InlineData("secret:own-id")]
    [InlineData("own-id")]
    public async Task GetSecretAsync_ResolvesOwnReference(string reference)
    {
        var accessor = CreateAccessor(("own-id", OwnValue));

        Assert.Equal(OwnValue, await accessor.GetSecretAsync(reference, default));
    }

    [Fact]
    public async Task GetSecretAsync_RejectsReferenceOutsideOwnConfig()
    {
        // The source holds both secrets; this plugin's config only names its own.
        var accessor = CreateAccessor(allowed: ["own-id"], ("own-id", OwnValue), ("other-id", OtherValue));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessor.GetSecretAsync("secret:other-id", default).AsTask());

        Assert.Contains("secret:other-id", error.Message);
        Assert.DoesNotContain(OwnValue, error.Message);
        Assert.DoesNotContain(OtherValue, error.Message);
    }

    [Fact]
    public async Task GetSecretAsync_RejectsReferenceThatDoesNotResolve()
    {
        // Named in the plugin's config but absent from the secret source.
        var accessor = CreateAccessor(allowed: ["missing-id"]);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessor.GetSecretAsync("secret:missing-id", default).AsTask());

        Assert.Contains("secret:missing-id", error.Message);
        Assert.DoesNotContain(OwnValue, error.Message);
    }

    [Fact]
    public async Task GetSecretAsync_RejectsNullName()
    {
        var accessor = CreateAccessor(("own-id", OwnValue));

        await Assert.ThrowsAsync<ArgumentNullException>(() => accessor.GetSecretAsync(null!, default).AsTask());
    }

    [Fact]
    public void Constructor_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(
            () => new ScopedSecretAccessor(null!, new HashSet<string>(StringComparer.Ordinal)));
        Assert.Throws<ArgumentNullException>(
            () => new ScopedSecretAccessor(new FakeSecretSource(), null!));
    }

    [Fact]
    public async Task Factory_ScopesEachPluginToItsOwnSection()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:a:ClientId"] = "secret:a-id",
            ["CredProx:Credentials:a:ClientSecret"] = "secret:a-secret",
            ["CredProx:Credentials:b:ClientId"] = "secret:b-id",
        }).Build();

        var source = new FakeSecretSource(("a-id", "a-value"), ("a-secret", "a-secret-value"), ("b-id", "b-value"));
        var factory = new SecretAccessorFactory(source);

        var accessorA = factory.CreateAccessor(configuration.GetSection("CredProx:Credentials:a"));
        var accessorB = factory.CreateAccessor(configuration.GetSection("CredProx:Credentials:b"));

        Assert.Equal("a-value", await accessorA.GetSecretAsync("secret:a-id", default));
        Assert.Equal("a-secret-value", await accessorA.GetSecretAsync("secret:a-secret", default));
        Assert.Equal("b-value", await accessorB.GetSecretAsync("secret:b-id", default));

        // Cross-section reads are refused in both directions.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessorA.GetSecretAsync("secret:b-id", default).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessorB.GetSecretAsync("secret:a-id", default).AsTask());
    }

    [Fact]
    public void Factory_RejectsNullSection()
    {
        var factory = new SecretAccessorFactory(new FakeSecretSource());

        Assert.Throws<ArgumentNullException>(() => factory.CreateAccessor(null!));
    }

    [Fact]
    public void Constructor_Factory_RejectsNullSource()
    {
        Assert.Throws<ArgumentNullException>(() => new SecretAccessorFactory(null!));
    }

    [Fact]
    public async Task DynamicName_ResolvesExpandedName()
    {
        // §3.2 acme: the plugin declares secret:acme-{partition}-user and the provider
        // requests the expanded name for this request's partition.
        var accessor = CreateAccessor(allowed: ["acme-{partition}-user"], ("acme-uat-user", OwnValue));

        Assert.Equal(OwnValue, await accessor.GetSecretAsync("secret:acme-uat-user", default));
    }

    [Theory]
    [InlineData("acme-uat-pass")] // different shape suffix
    [InlineData("other-uat-user")] // different shape prefix
    [InlineData("acme-{partition}-user")] // the unexpanded declaration is not a name
    [InlineData("acme-uat-user-extra")] // anchored: the shape must match the whole name
    public async Task DynamicName_RejectsNamesOutsideTheDeclaredShape(string reference)
    {
        var accessor = CreateAccessor(
            allowed: ["acme-{partition}-user"],
            ("acme-uat-user", OwnValue),
            ("acme-uat-pass", OtherValue),
            ("other-uat-user", OtherValue),
            ("acme-{partition}-user", OtherValue),
            ("acme-uat-user-extra", OtherValue));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessor.GetSecretAsync(reference, default).AsTask());

        Assert.Contains(reference, error.Message);
        Assert.DoesNotContain(OwnValue, error.Message);
        Assert.DoesNotContain(OtherValue, error.Message);
    }

    [Fact]
    public async Task FullyDynamicName_MatchesAnyBraceFreeName()
    {
        // Pins the documented semantics: a declaration of secret:{partition} admits every
        // name. Config authors must keep placeholders narrow; this is why the plan's own
        // examples always carry a static prefix.
        var accessor = CreateAccessor(allowed: ["{partition}"], ("anything-at-all", OwnValue));

        Assert.Equal(OwnValue, await accessor.GetSecretAsync("secret:anything-at-all", default));
    }

    [Fact]
    public async Task MalformedDeclaration_MatchesItselfLiterally()
    {
        // An unterminated placeholder is literal text, not a wildcard: fails closed for
        // anything but the exact (malformed) name.
        var accessor = CreateAccessor(allowed: ["a{b"], ("a{b", OwnValue));

        Assert.Equal(OwnValue, await accessor.GetSecretAsync("secret:a{b", default));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => accessor.GetSecretAsync("secret:aXb", default).AsTask());
    }

    [Fact]
    public async Task Factory_ScopesDynamicNamesFromTheLoginExchangeCredential()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:acme:LoginEndpoint"] =
                "https://signin.{partition}.acme.com/basicauth?tenant_id={secret:acme-{partition}-tenantid}",
            ["CredProx:Credentials:acme:Basic:User"] = "secret:acme-{partition}-user",
            ["CredProx:Credentials:contoso:ClientId"] = "secret:contoso-client-id",
        }).Build();

        var source = new FakeSecretSource(
            ("acme-uat-tenantid", "tenant-value"),
            ("acme-uat-user", "user-value"),
            ("contoso-client-id", "contoso-value"));
        var factory = new SecretAccessorFactory(source);

        var acme = factory.CreateAccessor(configuration.GetSection("CredProx:Credentials:acme"));

        Assert.Equal("tenant-value", await acme.GetSecretAsync("secret:acme-uat-tenantid", default));
        Assert.Equal("user-value", await acme.GetSecretAsync("secret:acme-uat-user", default));

        // Other plugins' secrets stay out of reach, and so do names outside the shapes.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => acme.GetSecretAsync("secret:contoso-client-id", default).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => acme.GetSecretAsync("secret:acme-uat-password", default).AsTask());
    }

    private static ScopedSecretAccessor CreateAccessor(params (string Name, string Value)[] ownSecrets) =>
        CreateAccessor(ownSecrets.Select(s => s.Name).ToArray(), ownSecrets);

    private static ScopedSecretAccessor CreateAccessor(string[] allowed, params (string Name, string Value)[] sourceSecrets) =>
        new(new FakeSecretSource(sourceSecrets), allowed.ToHashSet(StringComparer.Ordinal));

    private sealed class FakeSecretSource(params (string Name, string Value)[] secrets) : ISecretSource
    {
        private readonly Dictionary<string, string> _secrets = secrets.ToDictionary(s => s.Name, s => s.Value, StringComparer.Ordinal);

        public string Scheme => "secret";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new(_secrets.TryGetValue(name, out var value) ? value : null);

        public Microsoft.Extensions.Primitives.IChangeToken GetChangeToken() =>
            new Microsoft.Extensions.Primitives.CancellationChangeToken(CancellationToken.None);
    }
}
