using System.Reflection;
using CredProx;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The two operator pages written by the M45 docs round carry the same risk
/// <see cref="ProductionDocGuardTests"/> guards in <c>docs/production.md</c>: every API call
/// and every option name they print must exist on the shipped surface, or the page instructs
/// a deploy that fails. Widened per the lead's 2026-11-19 decision, with <c>docs/upgrading.md</c>
/// line 21 (the parameterless <c>AddCredProxThrottling()</c> the 0.12 split table shipped with)
/// as the shape this must catch: name-exists-greps pass on that typo, a signature match does
/// not — so call checks compare parameter counts against the real overloads via reflection,
/// never a text grep.
/// </summary>
public sealed class OpsDocsSurfaceGuardTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "credprox-plan.md")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string Doc(string name) => File.ReadAllText(Path.Combine(RepoRoot(), "docs", name));

    private static IEnumerable<Assembly> AnchorAssemblies() => new[]
    {
        typeof(CredProxCoreOptions),
        typeof(StaticKeyOptions),
        typeof(OAuthClientCredentialsOptions),
        typeof(HmacOptions),
        typeof(LoginExchangeOptions),
        typeof(CallerKeyOptions),
        typeof(CallerTokenOptions),
        typeof(CredProxOperationsServiceCollectionExtensions),
    }.Select(t => t.Assembly).Distinct();

    /// <summary>Every <c>AddCredProx…(…)</c> call printed in upgrading.md must ship as a public
    /// static extension with an overload accepting the documented number of arguments, on the
    /// receiver the doc prints it against: the service collection, or the
    /// <c>IReverseProxyBuilder</c> a call printed right after <c>AddReverseProxy().</c> rides on.</summary>
    [Fact]
    public void UpgradingDoc_EveryAddCallMatchesAShippedSignature()
    {
        var doc = Doc("upgrading.md");
        var calls = System.Text.RegularExpressions.Regex
            .Matches(doc, @"AddCredProx[A-Za-z0-9]*(?=\()")
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(calls);
        var shipped = AnchorAssemblies()
            .SelectMany(a => a.GetExportedTypes().Where(t => t.IsSealed && t.IsAbstract))
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Where(m => m.GetParameters().Length > 0 && typeof(Microsoft.Extensions.DependencyInjection.IServiceCollection)
                .IsAssignableFrom(m.GetParameters()[0].ParameterType))
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);
        // Guard domain: the literal "(...)" arity carve-out below (names must ship, arity of
        // "fill in your arguments" rows does not), Options-member resolution by public
        // instance property with IgnoreCase, and the fact that the rotation runbook as
        // shipped prints exactly one Options.Member pair today.
        // Arity per documented call: "(builder.Configuration)" → 1, "()" → 0 (the extension
        // receiver is not counted; args split on commas outside generics).
        foreach (var match in System.Text.RegularExpressions.Regex.Matches(doc, @"(AddCredProx[A-Za-z0-9]*)\(([^()]*(?:<[^<>]*>[^()]*)*)\)").Cast<System.Text.RegularExpressions.Match>())
        {
            var name = match.Groups[1].Value;
            var argText = match.Groups[2].Value.Trim();
            if (argText == "...")
            {
                continue; // documented as "fill in your arguments" (caller-auth rows): the
                          // name must ship (checked below), arity is deliberately not pinned
            }
            var depth = 0;
            var arity = argText.Length == 0 ? 0 : 1;
            foreach (var ch in argText)
            {
                if (ch is '<' or '(') depth++;
                else if (ch is '>' or ')') depth--;
                else if (ch == ',' && depth == 0) arity++;
            }
            // Receiver group keyed off the printed context: a call right after
            // "AddReverseProxy()." is the reverse-proxy hookup and resolves against the
            // IReverseProxyBuilder receiver; every other call resolves against the
            // service collection, exactly as before. A wrong-arity call in either group
            // still fails the arity assert below.
            var before = doc[Math.Max(0, match.Index - 40)..match.Index];
            var rp = before.LastIndexOf("AddReverseProxy().", StringComparison.Ordinal);
            var reverseProxyCall = rp >= 0
                && before[(rp + "AddReverseProxy().".Length)..].Trim(' ', '…').Length == 0;
            var receiver = reverseProxyCall
                ? typeof(Microsoft.Extensions.DependencyInjection.IReverseProxyBuilder)
                : typeof(Microsoft.Extensions.DependencyInjection.IServiceCollection);
            var overloads = AnchorAssemblies()
                .SelectMany(a => a.GetExportedTypes().Where(t => t.IsSealed && t.IsAbstract))
                .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                .Where(m => m.Name == name
                    && m.GetParameters().Length > 0
                    && receiver.IsAssignableFrom(m.GetParameters()[0].ParameterType))
                .ToList();
            Assert.True(overloads.Count > 0,
                $"'{name}()' is printed in docs/upgrading.md {(reverseProxyCall ? "after AddReverseProxy()." : "on the service collection")} but no public static AddCredProx extension with that receiver ships.");
            var arities = overloads.Select(m => m.GetParameters().Length - 1).Distinct().ToList();
            Assert.True(arities.Contains(arity),
                $"'{name}' is printed in docs/upgrading.md with {arity} argument(s) but the shipped overloads take {string.Join("/", arities)} (beyond the receiver argument).");
        }
        // Nothing in the table row column may be a name-only citation that does not exist:
        foreach (var name in calls)
        {
            Assert.True(shipped.Contains(name), $"'{name}' is cited in docs/upgrading.md but no such AddCredProx extension ships.");
        }
    }

    /// <summary>Every <c>SomethingOptions.Member</c> pair printed in the rotation runbook must
    /// resolve to a public instance property on an exported options type. Host-framework names
    /// (AddAzureKeyVault, ReloadInterval, the JWKS cache) do not match this pattern and stay
    /// attributed to their packages by the page's own wording.</summary>
    [Fact]
    public void RotationDoc_EveryOptionsMemberPairResolves()
    {
        var doc = Doc(Path.Combine("operations", "credential-rotation.md"));
        var pairs = System.Text.RegularExpressions.Regex
            .Matches(doc, @"\b([A-Z][A-Za-z0-9]*Options)\.([A-Za-z][A-Za-z0-9]*)\b")
            .Select(m => (Type: m.Groups[1].Value, Prop: m.Groups[2].Value))
            .Distinct()
            .ToList();
        Assert.NotEmpty(pairs);
        var optionTypes = AnchorAssemblies()
            .SelectMany(a => a.GetExportedTypes())
            .Where(t => t.Name.EndsWith("Options", StringComparison.Ordinal))
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);
        var typesByName = AnchorAssemblies()
            .SelectMany(a => a.GetExportedTypes())
            .Where(t => t.Name.EndsWith("Options", StringComparison.Ordinal))
            .GroupBy(t => t.Name, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IEnumerable<Type>)g, StringComparer.Ordinal);
        foreach (var (typeName, prop) in pairs)
        {
            Assert.True(optionTypes.Contains(typeName),
                $"'{typeName}.{prop}' is printed in the rotation runbook but no exported {typeName} ships.");
            var resolved = typesByName[typeName].Any(t =>
                t.GetProperty(prop, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase) is not null);
            Assert.True(resolved, $"'{typeName}.{prop}' is printed in the rotation runbook but {typeName} has no such public property.");
        }
    }

    /// <summary>Flat <c>CredProx:</c> section citations in the rotation runbook must root on a
    /// real configuration section (placeholder segments like <c>&lt;callerId&gt;</c> never
    /// reach the check — the token pattern stops at them).</summary>
    [Fact]
    public void RotationDoc_ConfigKeysRootOnRealSections()
    {
        var doc = Doc(Path.Combine("operations", "credential-rotation.md"));
        var sections = CoreSections();
        var tokens = System.Text.RegularExpressions.Regex
            .Matches(doc, @"(?<!/)CredProx:[A-Za-z][A-Za-z0-9]*(?::[A-Za-z][A-Za-z0-9]*)*")
            .Select(m => m.Value.TrimEnd(':'))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(tokens);
        foreach (var token in tokens)
        {
            var root = token.Split(':')[1];
            Assert.True(sections.Contains(root),
                $"'{token}' roots on '{root}', which is not a CredProx section (known: {string.Join(", ", sections)}).");
        }
    }

    private static IReadOnlySet<string> CoreSections()
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "src", "CredProx", "CredProxReverseProxyBuilderExtensions.cs"));
        var start = text.IndexOf("CoreSections", StringComparison.Ordinal);
        Assert.True(start >= 0, "CoreSections moved out of CredProxReverseProxyBuilderExtensions.cs — update this guard's parser.");
        var body = text.Substring(start, text.IndexOf('}', start) - start);
        return System.Text.RegularExpressions.Regex.Matches(body, "\"([A-Za-z]+)\"")
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}
