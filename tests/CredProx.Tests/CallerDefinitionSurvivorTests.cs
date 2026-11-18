using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the caller model types: <see cref="CallerOperationRule"/>'s
/// null-collections-as-empty contract, and <see cref="CallerDefinition"/>'s constructor
/// guards. (The former <c>CallerKey</c> model guards left with the type: key-entry shape
/// is now validated by the keys package's registry rules, pinned there.)
/// </summary>
public sealed class CallerDefinitionSurvivorTests
{
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
        var operations = new[] { new CallerOperationRule("reports", ["GET"], ["/reports/*"]) };

        Assert.Throws<ArgumentNullException>(() => new CallerDefinition(null!, operations));
        Assert.Throws<ArgumentException>(() => new CallerDefinition("", operations));
        Assert.Throws<ArgumentNullException>(() => new CallerDefinition("app-a", null!));
    }
}
