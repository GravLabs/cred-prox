using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the fail-closed unknown-key walker: startup rejection does not
/// leak the credential-only Type/Preset keys, an unknown key stays one error instead of
/// cascading into a nesting complaint, nested blocks never re-allow Type/Preset, typed
/// option dictionaries check their entry keys while scalar dictionaries stay untouched
/// leaves, and every error message keeps its exact guidance text.
/// </summary>
public sealed class ConfigKeyValidatorSurvivorTests
{
    private static List<string> Walk(Type optionsType, params (string Key, string Value)[] entries)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => "S:" + e.Key, e => (string?)e.Value))
            .Build();
        var errors = new List<string>();
        ConfigKeyValidator.RejectUnknownKeys(
            config.GetSection("S"), optionsType, "thing 't'", "S", errors);
        return errors;
    }

    private static List<string> WalkAllowed(
        IReadOnlyDictionary<string, Type?> allowed, params (string Key, string Value)[] entries)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => "S:" + e.Key, e => (string?)e.Value))
            .Build();
        var errors = new List<string>();
        ConfigKeyValidator.RejectUnknownKeys(config.GetSection("S"), allowed, "thing 't'", "S", errors);
        return errors;
    }

    // ---- synthetic option shapes ----

    public sealed class InnerOptions
    {
        public int P { get; set; }
    }

    public sealed class NestedTypeOptions
    {
        public InnerOptions Inner { get; set; } = new();
    }

    public sealed class DictComplexOptions
    {
        public Dictionary<string, InnerOptions> Clusters { get; set; } = new();
    }

    public sealed class DictScalarOptions
    {
        public Dictionary<string, string> Map { get; set; } = new();
    }

    public sealed class NullableIntOptions
    {
        public int? Timeout { get; set; }
    }

    public sealed class MixedPropsBlock
    {
        public int A { get; set; }

        public string Computed => "c";
    }

    public sealed class MixedPropsOptions
    {
        public MixedPropsBlock Mixed { get; set; } = new();
    }

    public sealed class WeirdSeq : IComparable<WeirdSeq>, IEnumerable<InnerOptions>
    {
        public int CompareTo(WeirdSeq? other) => 0;

        public IEnumerator<InnerOptions> GetEnumerator() => ((IEnumerable<InnerOptions>)Array.Empty<InnerOptions>()).GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public sealed class SeqOptions
    {
        public WeirdSeq Seq { get; set; } = new();
    }

    public sealed class ListOptions
    {
        public List<string> Allowed { get; set; } = new();
    }

    public sealed class IndexerOptions
    {
        public int Timeout { get; set; }

        public InnerOptions this[string key] => new();
    }

    // ---- startup overload ----

    [Fact]
    public void Startup_OverloadDoesNotAdmitTypeOrPreset()
    {
        // Type/Preset belong to credential roots only; a host options section that admits
        // them would silently accept a key no binder consumes there.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["T:Type"] = "whatever" })
            .Build();

        var ex = Assert.Throws<OptionsValidationException>(
            () => ConfigKeyValidator.RejectUnknownKeysAtStartup(config, "T", typeof(CallerKeyOptions)));

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("unknown configuration key 'Type'", failure, StringComparison.Ordinal);
        Assert.Contains("'T' section", failure, StringComparison.Ordinal);
    }

    // ---- walker shape ----

    [Fact]
    public void UnknownKeyWithChildren_DoesNotCascadeIntoANestingError()
    {
        var errors = Walk(typeof(NestedTypeOptions), ("Bogus:Inner", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("unknown configuration key 'Bogus'", failure, StringComparison.Ordinal);
        Assert.Contains("silently drop the setting it was meant to control", failure, StringComparison.Ordinal);
        Assert.EndsWith("fix the spelling or remove the key.", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void NestedComplexBlock_DoesNotReAllowTypeOrPreset()
    {
        // Type/Preset are consumed only at the credential root; a nested block that accepts
        // them binds nothing and hides the mistake.
        var errors = Walk(typeof(NestedTypeOptions), ("Inner:Type", "x"));

        var failure = Assert.Single(errors);
        Assert.Contains("unknown configuration key 'Inner:Type'", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void DictionaryOfOptions_ChecksEachEntryKey()
    {
        var errors = Walk(typeof(DictComplexOptions), ("Clusters:acme:Bogus", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("unknown configuration key 'Clusters:acme:Bogus'", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void DictionaryOfScalars_IsAnUntouchedLeaf()
    {
        // User-defined keys with scalar values: the walker must not start validating
        // "keys" against string — every key would look unknown.
        var errors = Walk(typeof(DictScalarOptions), ("Map:canary", "1"), ("Map:canary:Depth", "1"));

        Assert.Empty(errors);
    }

    [Fact]
    public void NullableInt_IsAScalar_NestedBlockIsRejected()
    {
        var errors = Walk(typeof(NullableIntOptions), ("Timeout:Inner", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("nested block under 'Timeout'", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void BlockWithOneSettableProperty_IsRecurseNotNest()
    {
        // One public settable property is enough to be a bindable block (Any, not All):
        // the descent reports the inner key, not a bogus nesting complaint.
        var errors = Walk(typeof(MixedPropsOptions), ("Mixed:X", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("unknown configuration key 'Mixed:X'", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void EnumerableOfComplex_IsNotTreatedAsIndexedList()
    {
        // WeirdSeq's first generic interface is IComparable<WeirdSeq>, not the enumeration:
        // element-type resolution must find IEnumerable<InnerOptions>. Picking the wrong
        // interface yields a non-complex element and the list-index branch rejects a user key.
        var errors = Walk(typeof(SeqOptions), ("Seq:Bogus", "1"));

        Assert.Empty(errors);
    }

    [Fact]
    public void ScalarNesting_ListsDroppedKeysOrderedAndJoined()
    {
        // The value-only key (null type in the explicit set) rejects blocks under it,
        // listing exactly what gets dropped — ordered, comma-separated, fix included.
        var errors = WalkAllowed(
            new Dictionary<string, Type?> { ["Cert"] = null },
            ("Cert:zeta", "1"),
            ("Cert:alpha", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("takes a single value (found Cert:alpha, Cert:zeta)", failure, StringComparison.Ordinal);
        Assert.Contains(
            "remove the nesting or move the keys to the block that owns them", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void ListEntry_NonIndexKey_GivesTheIndexGuidance()
    {
        var errors = Walk(typeof(ListOptions), ("Allowed:acme", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("inside the list 'Allowed'", failure, StringComparison.Ordinal);
        Assert.Contains("must be indexed ('Allowed:0', 'Allowed:1', …)", failure, StringComparison.Ordinal);
        Assert.EndsWith("index it or remove it.", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Indexer_IsNotAConfigurationKey()
    {
        // Indexers are skipped when listing bindable keys; treating the indexer as a block
        // would let a foreign "Item" section through and complain about its contents.
        var errors = Walk(typeof(IndexerOptions), ("Item:Bogus", "1"));

        var failure = Assert.Single(errors);
        Assert.Contains("unknown configuration key 'Item' under 'S'", failure, StringComparison.Ordinal);
        Assert.DoesNotContain("Item:Bogus", failure, StringComparison.Ordinal);
    }
}
