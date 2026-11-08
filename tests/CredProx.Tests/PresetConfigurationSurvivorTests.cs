using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="PresetConfiguration"/>: the removed-built-in-preset
/// diagnosis (each name and each sample path is operator-facing text), the
/// unknown-preset branch, and the fragment flattener (array indices, raw text for
/// non-string leaves).
/// </summary>
public sealed class PresetConfigurationSurvivorTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] entries)
    {
        var dictionary = entries.ToDictionary(e => "CredProx:" + e.Key, e => e.Value);
        return new ConfigurationBuilder().AddInMemoryCollection(dictionary).Build();
    }

    [Theory]
    [InlineData("spotify", "samples/Spotify")]
    [InlineData("microsoft-graph", "samples/MicrosoftGraph")]
    [InlineData("github-app", "samples/GitHubApp")]
    [InlineData("keycloak", "samples/OAuthKeycloak")]
    [InlineData("adp", "samples/ADP")]
    [InlineData("cayuse", "samples/LoginExchange")]
    public void RemovedBuiltInPreset_NamesThePresetAndItsSample(string presetName, string sample)
    {
        var configuration = Config(("Credentials:c:Preset", presetName));
        var errors = new List<string>();

        PresetConfiguration.Compose(configuration, [], errors);

        var error = Assert.Single(errors);
        Assert.Equal(
            $"The credential 'c' references the built-in preset '{presetName}', which was removed in 0.4.0. " +
            $"Configure the vendor explicitly — the full config is in {sample}.",
            error);
    }

    [Fact]
    public void UnknownPreset_ReportsUnknown_NotShapeError()
    {
        // A missing preset must not resolve to a default fragment (which would take the
        // "is not a JSON object" branch instead of naming the unknown preset).
        var configuration = Config(("Credentials:c:Preset", "ghost"));
        var errors = new List<string>();

        PresetConfiguration.Compose(configuration, [], errors);

        var error = Assert.Single(errors);
        Assert.Equal("The credential 'c' references unknown preset 'ghost'.", error);
    }

    [Fact]
    public void Compose_FlattensArrayIndicesAndKeepsRawTextForNonStrings()
    {
        var configuration = Config(("Credentials:c:Preset", "rich"));
        var errors = new List<string>();

        var composed = PresetConfiguration.Compose(
            configuration, [new StubPresetSource()], errors);

        Assert.Empty(errors);
        Assert.Equal("StaticKey", composed["CredProx:Credentials:c:Type"]);
        Assert.Equal("read", composed["CredProx:Credentials:c:Scopes:0"]);
        Assert.Equal("write", composed["CredProx:Credentials:c:Scopes:1"]);
        Assert.Equal("30", composed["CredProx:Credentials:c:Timeout"]); // raw text, not GetString()
        Assert.Equal("false", composed["CredProx:Credentials:c:Flag"]);
    }

    private sealed class StubPresetSource : IPresetSource
    {
        public bool TryGetPreset(string name, out JsonElement preset)
        {
            if (name == "rich")
            {
                preset = JsonDocument.Parse(
                    """
                    { "Type": "StaticKey", "Scopes": ["read", "write"], "Timeout": 30, "Flag": false }
                    """).RootElement.Clone();
                return true;
            }

            preset = default;
            return false;
        }
    }
}
