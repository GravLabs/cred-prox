using System.Text.Json;
using CredProx;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="ConfigurationPresetSource"/>: the name guard, the
/// present/absent detection on both section shapes (scalar value versus children), and
/// the array-shape rebuild (all-numeric child keys, index order, per-item recursion).
/// </summary>
public sealed class ConfigurationPresetSourceTests
{
    private static ConfigurationPresetSource Source(params (string Key, string? Value)[] entries) =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => "CredProx:" + e.Key, e => e.Value))
            .Build());

    [Fact]
    public void TryGetPreset_RejectsNullOrEmptyName()
    {
        var source = Source(("Presets:known:Type", "StaticKey"));

        Assert.Throws<ArgumentNullException>(() => source.TryGetPreset(null!, out _));
        var empty = Assert.Throws<ArgumentException>(() => source.TryGetPreset(string.Empty, out _));
        Assert.Equal("name", empty.ParamName);
    }

    [Fact]
    public void TryGetPreset_UnknownName_ReturnsFalse()
    {
        var source = Source(("Presets:known:Type", "StaticKey"));

        Assert.False(source.TryGetPreset("ghost", out var fragment));
        Assert.Equal(JsonValueKind.Undefined, fragment.ValueKind);
    }

    [Fact]
    public void TryGetPreset_ScalarSection_IsAStringFragment()
    {
        // A value on the preset node itself (no children) is a present, malformed preset —
        // it must resolve (the shape error belongs to the validator, not the source).
        var source = Source(("Presets:p", "StaticKey"));

        Assert.True(source.TryGetPreset("p", out var fragment));
        Assert.Equal(JsonValueKind.String, fragment.ValueKind);
        Assert.Equal("StaticKey", fragment.GetString());
    }

    [Fact]
    public void TryGetPreset_MixedChildKeys_StayAnObject()
    {
        // One numeric key among named children must not trip the array shape (the All to
        // Any mutant parses the named key as an index and throws).
        var source = Source(
            ("Presets:m:0", "a"),
            ("Presets:m:Name", "b"));

        Assert.True(source.TryGetPreset("m", out var fragment));
        Assert.Equal(JsonValueKind.Object, fragment.ValueKind);
        Assert.Equal("a", fragment.GetProperty("0").GetString());
        Assert.Equal("b", fragment.GetProperty("Name").GetString());
    }

    [Fact]
    public void TryGetPreset_NumericChildKeys_BecomeAnOrderedArray()
    {
        var source = Source(
            ("Presets:a:1", "b"),
            ("Presets:a:0", "a"));

        Assert.True(source.TryGetPreset("a", out var fragment));
        Assert.Equal(JsonValueKind.Array, fragment.ValueKind);
        Assert.Equal(2, fragment.GetArrayLength()); // per-child Add is load-bearing
        Assert.Equal("""["a","b"]""", fragment.GetRawText()); // numeric index order, not insertion order
    }

    [Fact]
    public void TryGetPreset_NestedObject_AndNulls()
    {
        // Null members carry nothing (the host value or default stands); objects recurse.
        var source = Source(
            ("Presets:n:Type", "StaticKey"),
            ("Presets:n:Prefix", (string?)null),
            ("Presets:n:Partition:Name", "p"));

        Assert.True(source.TryGetPreset("n", out var fragment));
        Assert.Equal(JsonValueKind.Object, fragment.ValueKind);
        Assert.Equal("p", fragment.GetProperty("Partition").GetProperty("Name").GetString());
        Assert.Equal(JsonValueKind.Null, fragment.GetProperty("Prefix").ValueKind);
    }
}
