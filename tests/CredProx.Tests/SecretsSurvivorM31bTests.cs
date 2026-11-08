using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (Secrets): the two public entry guards were absorbed by the
/// reference walker's own null throw — same exception type, so only a paramName pin
/// separates the documented contract from the accident. The diagnosis order and the
/// brace-skip rule are the other two untested decisions.
/// </summary>
public sealed class SecretsSurvivorM31bTests
{
    private sealed class FakeSecretSource(params (string Name, string Value)[] secrets) : ISecretSource
    {
        private readonly Dictionary<string, string> _secrets =
            secrets.ToDictionary(s => s.Name, s => s.Value, StringComparer.Ordinal);

        public string Scheme => "secret";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new(_secrets.TryGetValue(name, out var value) ? value : null);

        public IChangeToken GetChangeToken() => new CancellationChangeToken(CancellationToken.None);
    }

    private static IConfigurationSection Configuration(params (string Key, string? Value)[] data) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(data.ToDictionary(d => d.Key, d => d.Value, StringComparer.OrdinalIgnoreCase))
            .Build()
            .GetSection("CredProx");

    [Fact]
    public void CreateAccessor_NullSection_ThrowsArgumentNullNamingPluginSection()
    {
        var factory = new SecretAccessorFactory(new FakeSecretSource());

        var error = Assert.Throws<ArgumentNullException>(() => factory.CreateAccessor(null!));
        Assert.Equal("pluginSection", error.ParamName); // not the walker's incidental name
    }

    [Fact]
    public async Task ValidateAsync_NullSection_ThrowsArgumentNullNamingCredProxSection()
    {
        var validator = new SecretReferenceValidator(new FakeSecretSource());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => validator.ValidateAsync(null!, default).AsTask());
        Assert.Equal("credProxSection", error.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_MultipleMissing_ErrorsAreOrdinalOrdered()
    {
        // Operator-readable determinism: the same bad config must produce the same
        // diagnosis order every boot.
        var validator = new SecretReferenceValidator(new FakeSecretSource());

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.ValidateAsync(
            Configuration(
                ("CredProx:Credentials:c1:ClientId", "secret:zeta-missing"),
                ("CredProx:Credentials:c2:ClientId", "secret:alpha-missing")),
            default).AsTask());

        var failures = error.Failures.ToList();
        Assert.Equal(2, failures.Count);
        Assert.Contains("alpha-missing", failures[0], StringComparison.Ordinal);
        Assert.Contains("zeta-missing", failures[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidateAsync_UnbalancedBrace_StillSkippedAsTemplated()
    {
        // An unterminated placeholder is a templated name, fail-closed: it must not be
        // probed at startup (it cannot resolve) and must not error.
        var validator = new SecretReferenceValidator(new FakeSecretSource());

        await validator.ValidateAsync(
            Configuration(("CredProx:Credentials:acme:User", "secret:acme-{partition")),
            default);
    }
}
