using CredProx;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Direct unit coverage of the template engine (§3.2 forms, §3.5 rule 4): the argument
/// guards and the injection invariant that resolved secret values are never re-scanned
/// for further expansion. M31 mutation triage found the engine was only covered through
/// binder and accessor suites, which never passed null arguments or a hostile value.
/// </summary>
public sealed class TemplateExpanderTests
{
    [Fact]
    public async Task NullTemplate_Throws_NamingTemplate()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            TemplateExpander.ExpandAsync(
                null!, "p", TestSecrets.AccessorFor(new()), default).AsTask());

        Assert.Equal("template", ex.ParamName);
    }

    // Without the guard a reference-free template expands and returns cleanly, so the
    // exception itself is the only observable.
    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            TemplateExpander.ExpandAsync("plain-value", "p", null!, default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    // The injection invariant: a secret value that itself spells a reference must reach
    // the wire verbatim, never expanded against another credential's scope.
    [Fact]
    public async Task ResolvedValue_IsNeverRescanned()
    {
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:outer" },
            new() { ["outer"] = "prefix-{secret:inner}-suffix", ["inner"] = "STOLEN" });

        var value = await TemplateExpander.ExpandAsync(
            "token-{secret:outer}", "p", secrets, default);

        Assert.Equal("token-prefix-{secret:inner}-suffix", value);
    }

    [Fact]
    public async Task PartitionPlaceholder_ExpandsInsideSecretName()
    {
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:t-tenant-a" },
            new() { ["t-tenant-a"] = "t-value" });

        var value = await TemplateExpander.ExpandAsync(
            "secret:t-{partition}", "tenant-a", secrets, default);

        Assert.Equal("t-value", value);
    }

    // --- M31 mutation triage: the braced reference form ({secret:name}) had zero
    // coverage — the whole depth-matched scan cluster was NoCoverage in the sweep —
    // and the bare form's null-resolve throw was never reached, because the
    // production accessor throws internally; an accessor that returns null per
    // ISecretAccessor's contract must still produce the expander's own diagnosis. ---

    private sealed class MapAccessor(params (string Name, string Value)[] secrets) : ISecretAccessor
    {
        private readonly Dictionary<string, string> _map = secrets.ToDictionary(s => s.Name, s => s.Value);

        // The interface declares a non-nullable string but represents 'does not
        // resolve' as a runtime null — the expander's throw path keys on that.
        public ValueTask<string> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new(_map.TryGetValue(name, out var value) ? value : null!);
    }

    [Fact]
    public async Task BareReference_NullFromAccessor_NamesTheReference()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TemplateExpander.ExpandAsync("secret:gone", null, new MapAccessor(), default).AsTask());

        Assert.Contains("'secret:gone'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("does not resolve", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Braced_ReplacesReferenceInPlace()
    {
        var value = await TemplateExpander.ExpandAsync(
            "Bearer {secret:tok}", null, new MapAccessor(("tok", "T1")), default);

        Assert.Equal("Bearer T1", value);
    }

    [Fact]
    public async Task Braced_MultipleReferences_AllResolved()
    {
        var value = await TemplateExpander.ExpandAsync(
            "k={secret:a}&s={secret:b}", null, new MapAccessor(("a", "1"), ("b", "2")), default);

        Assert.Equal("k=1&s=2", value);
    }

    [Fact]
    public async Task Braced_NestedBracesInName_MatchedByDepth()
    {
        // The closing brace is found by depth, mirroring SecretReferences.FindInValue:
        // the name is 'a{b}', and the text after the match keeps scanning.
        var value = await TemplateExpander.ExpandAsync(
            "x{secret:a{b}}c", null, new MapAccessor(("a{b}", "N")), default);

        Assert.Equal("xNc", value);
    }

    [Fact]
    public async Task Braced_Unterminated_KeepsTextVerbatim()
    {
        // Never silently drop a broken reference: the text rides along so resolution
        // fails loudly where the value is used.
        var value = await TemplateExpander.ExpandAsync(
            "x{secret:abc", null, new MapAccessor(("abc", "V")), default);

        Assert.Equal("x{secret:abc", value);
    }

    [Fact]
    public async Task Braced_LoneBraceAfterReference_StaysLiteral()
    {
        // '{' characters that do not start a reference are copied verbatim by the
        // scan loop — the prefix check is per-position, not per-string.
        var value = await TemplateExpander.ExpandAsync(
            "{secret:a} {b}", null, new MapAccessor(("a", "V")), default);

        Assert.Equal("V {b}", value);
    }
}
