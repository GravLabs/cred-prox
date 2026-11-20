using CredProx;
using CredProx.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.ConformanceTests;

/// <summary>
/// The built-in token cache runs the plugin authors' cache conformance suite (§5.2
/// "Conformance": the same suites, no privileged path).
/// </summary>
public sealed class InMemoryTokenCacheConformance : TokenCacheConformanceTests<InMemoryTokenCache>
{
    protected override InMemoryTokenCache CreateCache() =>
        new(Options.Create(new TokenCacheOptions()), TimeProvider.System);
}

/// <summary>
/// The built-in configuration secret source runs the plugin authors' secret-source
/// conformance suite.
/// </summary>
public sealed class ConfigurationSecretSourceConformance : SecretSourceConformanceTests<CredProx.Abstractions.ISecretSource>
{
    private const string KnownValue = "conformance-known-value";

    // The built-in is internal since the 1.0 surface freeze; the suite runs over the
    // interface, instantiated concretely here (the conformance assembly sees internals).
    protected override CredProx.Abstractions.ISecretSource CreateSource() =>
        new ConfigurationSecretSource(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Secrets:known"] = KnownValue,
        }).Build());

    protected override (string Name, string Value) KnownSecret => ("known", KnownValue);
}
