using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the caller model types: <see cref="CallerKey"/>'s id and hash
/// guards, <see cref="CallerOperationRule"/>'s null-collections-as-empty contract, and
/// <see cref="CallerDefinition"/>'s constructor guards.
/// </summary>
public sealed class CallerDefinitionSurvivorTests
{
    private static byte[] Hash() => new byte[32];

    [Theory]
    [InlineData(null)] // ThrowIfNullOrEmpty: null is the ANE half
    [InlineData("")]   // empty is the AE half
    public void CallerKey_MissingKeyId_Throws(string? keyId)
    {
        Assert.Throws(keyId is null
            ? typeof(ArgumentNullException)
            : typeof(ArgumentException), () => new CallerKey(keyId!, Hash(), null));
    }

    [Fact]
    public void CallerKey_NullHash_ThrowsArgumentNull_NotNullReference()
    {
        // Without the guard the length check below dereferences null first — the exact
        // type separates the guard from the accident.
        Assert.Throws<ArgumentNullException>(() => new CallerKey("k1", null!, null));
    }

    [Fact]
    public void OperationRule_NullMethods_TreatedAsAny()
    {
        // null methods/patterns mean "no restriction", not "no argument": the ctor
        // coalesces both to empty, and empty means every operation passes.
        var rule = new CallerOperationRule("reports", null!, []);

        Assert.Empty(rule.Methods);
        Assert.True(rule.Matches("reports", "GET", "/reports/q1"));
    }

    [Fact]
    public void OperationRule_NullPathPatterns_TreatedAsAny()
    {
        var rule = new CallerOperationRule(null, ["GET"], null!);

        Assert.Empty(rule.PathPatterns);
        Assert.True(rule.Matches("anything", "GET", "/whatever"));
    }

    [Fact]
    public void Definition_GuardsItsConstructorArguments()
    {
        var keys = new[] { new CallerKey("k1", Hash(), null) };

        Assert.Throws<ArgumentNullException>(() => new CallerDefinition(null!, keys, []));
        Assert.Throws<ArgumentException>(() => new CallerDefinition("", keys, []));
        Assert.Throws<ArgumentNullException>(() => new CallerDefinition("app-a", null!, []));
        Assert.Throws<ArgumentNullException>(() => new CallerDefinition("app-a", keys, null!));
    }
}
