using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Entry-shape rules for <c>CredProx:Callers:&lt;id&gt;:TokenClientIds</c> live with the
/// key's owner (<c>CallerTokenClientIdRules</c>) because its mapper matches the entries
/// verbatim: blank, padded or double-listed client ids are refused, and a client id may
/// be listed by at most one caller (case-insensitively — the mapper matches tokens
/// case-insensitively too). The core runs the rules at host start and on every live
/// rebind; the live-host cells are in <see cref="CallerRegistryValidatorTests"/>. This
/// file pins the rule itself: the refusals it returns and the exact wording an operator
/// reads. The core binder still accepts the key name (a 0.11.0 config must bind) and
/// keeps the at-least-one-auth-path rule.
/// </summary>
public sealed class CallerTokenClientIdRuleTests
{
    private static IReadOnlyList<string> RuleErrors(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var callers = config.GetSection("CredProx:Callers").GetChildren()
            .Select(section => new CallerRegistryEntry(section.Key, section))
            .ToList();
        return new CallerTokenClientIdRules().Validate(callers);
    }

    [Fact]
    public void DuplicateClientIdAcrossCallers_RuleRefuses_NamingBothOwners()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "shared-client",
            ["CredProx:Callers:agent-2:TokenClientIds:0"] = "SHARED-CLIENT",
        });

        // The error names the entry as the second listing reads (verbatim) and both owners.
        Assert.Contains(
            "The client id 'SHARED-CLIENT' is listed by more than one caller ('agent-1' and 'agent-2').",
            errors);
    }

    [Fact]
    public void EmptyTokenClientEntry_RuleRefuses()
    {
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:TokenClientIds:1"] = "",
        });

        Assert.Contains(
            "The caller 'agent-1' has an empty TokenClientIds entry.",
            errors);
    }

    [Fact]
    public void WhitespacePaddedTokenClientEntry_RuleRefuses_NamingTheCallerAndKey()
    {
        // Padding must not bind silently — the entry looks right in the config, the
        // mapper matches verbatim, and it admits nobody.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = " client-abc ",
        });

        Assert.Single(errors);
        Assert.Contains("The caller 'agent-1' has a TokenClientIds entry with leading or trailing", errors[0]);
        Assert.Contains("a padded entry admits nobody", errors[0]);
    }

    [Fact]
    public void DuplicateClientIdInsideOneCaller_RuleRefuses_NamingItAsTwiceListed()
    {
        // A case-variant pair inside ONE caller is its own defect; the two-owner wording
        // would name the same caller twice and hide it.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-1:TokenClientIds:1"] = "CLIENT-ABC",
        });

        Assert.Contains(
            "The client id 'CLIENT-ABC' is listed twice by caller 'agent-1' "
                + "(client ids collide case-insensitively within a caller).",
            errors);
    }

    [Fact]
    public void CleanRegistry_RulePasses()
    {
        // The pass path so the refusals above are the rule's judgement, not a rule that
        // refuses every registry.
        var errors = RuleErrors(new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-abc",
            ["CredProx:Callers:agent-2:TokenClientIds:0"] = "client-def",
        });

        Assert.Empty(errors);
    }
}
