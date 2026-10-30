using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §3.3 validation: every <c>secret:</c> reference must resolve at startup; a missing one
/// produces one <see cref="OptionsValidationException"/> naming the reference, not the value.
/// </summary>
public sealed class SecretReferenceValidatorTests
{
    [Fact]
    public async Task ValidateAsync_AllReferencesResolve_DoesNotThrow()
    {
        var validator = new SecretReferenceValidator(new FakeSecretSource(("contoso-id", "v")));

        await validator.ValidateAsync(Configuration(("CredProx:Credentials:contoso:ClientId", "secret:contoso-id")), default);
    }

    [Fact]
    public async Task ValidateAsync_MissingReference_ThrowsNamingTheReferenceNotValues()
    {
        var validator = new SecretReferenceValidator(new FakeSecretSource(("contoso-id", "resolved-value")));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.ValidateAsync(
            Configuration(
                ("CredProx:Credentials:contoso:ClientId", "secret:contoso-id"),
                ("CredProx:Credentials:contoso:ClientSecret", "secret:contoso-missing")),
            default).AsTask());

        Assert.Contains("secret:contoso-missing", string.Join(Environment.NewLine, error.Failures));
        Assert.DoesNotContain("resolved-value", string.Join(Environment.NewLine, error.Failures));
    }

    [Fact]
    public async Task ValidateAsync_TemplatedReferencesAreSkippedAtStartup()
    {
        // The partition value is per-request, so the templated name cannot resolve at startup.
        var validator = new SecretReferenceValidator(new FakeSecretSource());

        await validator.ValidateAsync(
            Configuration(("CredProx:Credentials:acme:User", "secret:acme-{partition}-user")),
            default);
    }

    [Fact]
    public async Task ValidateAsync_FindsReferencesInNestedValuesAndTemplates()
    {
        var validator = new SecretReferenceValidator(new FakeSecretSource(("present", "v")));

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => validator.ValidateAsync(
            Configuration(("CredProx:Credentials:x:LoginEndpoint", "https://h/basicauth?tid={secret:absent}")),
            default).AsTask());

        Assert.Contains("secret:absent", string.Join(Environment.NewLine, error.Failures));
    }

    [Fact]
    public async Task ValidateAsync_RejectsNullSection()
    {
        var validator = new SecretReferenceValidator(new FakeSecretSource());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => validator.ValidateAsync(null!, default).AsTask());
    }

    [Fact]
    public void Constructor_RejectsNullSource()
    {
        Assert.Throws<ArgumentNullException>(() => new SecretReferenceValidator(null!));
    }

    private static IConfigurationSection Configuration(params (string Key, string? Value)[] data) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(data.ToDictionary(d => d.Key, d => d.Value, StringComparer.OrdinalIgnoreCase))
            .Build()
            .GetSection("CredProx");

    private sealed class FakeSecretSource(params (string Name, string Value)[] secrets) : ISecretSource
    {
        private readonly Dictionary<string, string> _secrets = secrets.ToDictionary(s => s.Name, s => s.Value, StringComparer.Ordinal);

        public string Scheme => "secret";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new(_secrets.TryGetValue(name, out var value) ? value : null);

        public IChangeToken GetChangeToken() => new CancellationChangeToken(CancellationToken.None);
    }
}
