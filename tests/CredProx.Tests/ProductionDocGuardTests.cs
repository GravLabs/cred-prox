using CredProx;
using System.Reflection;
using Xunit;
namespace CredProx.Tests;
/// <summary>
/// <c>docs/production.md</c> is an operator checklist whose value is that every name in it is
/// real: a renamed option or a drifted config key turns the page into an instruction that
/// fails a deploy. This guard re-reads the source of truth for the names it cites — the
/// fixed <c>CredProx:</c> section list, the route-metadata constants, the options types that
/// own each flat section, and the public <c>AddCredProx…</c> registration surface — and
/// refuses a doc that names something the code does not have.
/// </summary>
public sealed class ProductionDocGuardTests
{
    private static string Doc() => File.ReadAllText(Path.Combine(RepoRoot(), "docs", "production.md"));

    [Fact]
    public void ProductionDoc_EveryCredProxKeyLandsOnARealSection()
    {
        var doc = Doc();
        var sections = CoreSections();
        var metadata = MetadataNames();
        // (?<!/) keeps file-path citations (tests/CredProx.Tests/…) out: they name folders, not config names.
        var tokens = System.Text.RegularExpressions.Regex.Matches(doc, @"(?<!/)CredProx[:.][A-Za-z][A-Za-z0-9]*(?::[A-Za-z][A-Za-z0-9]*)*")
            .Select(m => m.Value.TrimEnd(':'))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(tokens);
        foreach (var token in tokens)
        {
            var separator = token.StartsWith("CredProx:", StringComparison.Ordinal) ? ':' : '.';
            var parts = token.Split(separator);
            var root = parts[1];
            var auditCategory = token.Equals(LoggerAuditSink.CategoryName, StringComparison.Ordinal);
            var isPackageId = CredProxAssemblyNames().Contains(token); // package ids are cited in full (CredProx.Operations)
            Assert.True(separator != '.' || metadata.Contains(root) || auditCategory || isPackageId,
                $"'{token}' is neither a route-metadata name, the audit category, nor a CredProx package id (constants: {string.Join(", ", metadata)}; category {LoggerAuditSink.CategoryName}).");
            if (separator == '.' && isPackageId)
            {
                continue; // a shipped-package citation, not a config section
            }
            if (separator == ':' && root == "InboundKeyHeader")
            {
                Assert.True(typeof(CredProx.CredProxCoreOptions).GetProperty("InboundKeyHeader") is not null, "InboundKeyHeader left CredProxCoreOptions.");
                continue;
            }
            Assert.True(sections.Contains(root) || metadata.Contains(root),
                $"'{token}' roots on '{root}', which is not a CredProx section (known: {string.Join(", ", sections)}).");
            if (parts.Length > 2 && FlatOptionOwners.TryGetValue(root, out var owner))
            {
                var property = owner!.GetProperty(parts[2], BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                Assert.True(property is not null, $"'{token}' names '{parts[2]}', which {owner.Name} does not have.");
            }
        }
    }

    [Fact]
    public void ProductionDoc_EveryAddCallExistsInShippedAssemblies()
    {
        var doc = Doc();
        var names = System.Text.RegularExpressions.Regex.Matches(doc, @"AddCredProx[A-Za-z0-9]*(?=\()")
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(names);
        var methods = AnchorAssemblies()
            .SelectMany(a => a.GetExportedTypes().Where(t => t.IsSealed && t.IsAbstract)) // static extension holders
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var name in names)
        {
            Assert.True(methods.Contains(name), $"'{name}()' is cited in the doc but no public static method of that name ships in the CredProx assemblies.");
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

    private static IEnumerable<Assembly> AnchorAssemblies() => new[]
    {
        typeof(CredProxCoreOptions),
        typeof(StaticKeyOptions),
        typeof(OAuthClientCredentialsOptions),
        typeof(HmacOptions),
        typeof(LoginExchangeOptions),
        typeof(CallerKeyOptions),
        typeof(CallerTokenOptions),
        typeof(TokenCredentialOptions),
        typeof(CredProxHealthOptions),
        typeof(CredProx.Abstractions.IAuditSink),
    }.Select(t => t.Assembly).Distinct();

    private static IReadOnlySet<string> CredProxAssemblyNames() =>
        AnchorAssemblies().Select(a => a.GetName().Name!).ToHashSet(StringComparer.Ordinal);

    private static IReadOnlySet<string> MetadataNames()
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "src", "CredProx", "Yarp", "CredProxMetadata.cs"));
        return System.Text.RegularExpressions.Regex.Matches(text, "\"CredProx\\.([A-Za-z0-9]+)\"")
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static readonly Dictionary<string, Type?> FlatOptionOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Audit"] = typeof(CredProxAuditOptions),
        ["Errors"] = typeof(CredProxErrorsOptions),
        ["Scrubbing"] = typeof(CredProxScrubbingOptions),
        ["Health"] = typeof(CredProxHealthOptions),
        ["CallerAuth"] = typeof(CallerKeyOptions),
        ["CallerToken"] = typeof(CallerTokenOptions),
    };

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
}
