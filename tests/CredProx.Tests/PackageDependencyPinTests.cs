using System.Xml.Linq;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// ADR-0007 sells six packages by one rule: install a package for the outside library it
/// brings. The table below mirrors docs/adr/0007-six-packages-one-entry-point.md decision 1
/// and the measured 0.14.0 table it replaced. A PackageReference added in the wrong place
/// does not just compile differently - it lands in every consumer's dependency graph through
/// the package's nuspec dependency group, which is exactly the drift the 0.12 split existed
/// to prevent. Nothing else reads a csproj, a nuspec or a package graph, so this pin is the
/// keeper: each package's outside dependencies are exactly its table row, and its internal
/// edges stay within the core and the abstractions (ADR-0005: never another feature package).
/// </summary>
public sealed class PackageDependencyPinTests
{
    // Outside libraries beyond ASP.NET Core, per ADR-0007. The identity row names the
    // Microsoft identity libraries plus the JWT bearer handler; the operations row names
    // the resilience package that brings Polly; the core row is YARP alone.
    private static readonly Dictionary<string, string[]> OutsideLibraries = new(StringComparer.Ordinal)
    {
        ["CredProx"] = ["Yarp.ReverseProxy"],
        ["CredProx.Abstractions"] = [],
        ["CredProx.Identity"] = ["Microsoft.AspNetCore.Authentication.JwtBearer", "Microsoft.IdentityModel.Protocols.OpenIdConnect"],
        ["CredProx.Azure"] = ["Azure.Core"],
        ["CredProx.Operations"] = ["Microsoft.Extensions.Http.Resilience"],
        ["CredProx.Testing"] = ["xunit"],
    };

    // These names ship inside Microsoft.AspNetCore.App: they ride the shared framework at
    // run time and are kept as package references only for the compile. They are already in
    // the published 0.14.0 core and Operations nuspec dependency groups (verified against
    // the shared framework directory), so they are part of the pinned set, not drift.
    private static readonly Dictionary<string, string[]> InFrameworkReferences = new(StringComparer.Ordinal)
    {
        ["CredProx"] = ["Microsoft.Extensions.Http", "Microsoft.Extensions.Hosting.Abstractions"],
        ["CredProx.Abstractions"] = [],
        ["CredProx.Identity"] = [],
        ["CredProx.Azure"] = [],
        ["CredProx.Operations"] = ["Microsoft.Extensions.Diagnostics.HealthChecks", "Microsoft.Extensions.Hosting.Abstractions"],
        ["CredProx.Testing"] = [],
    };

    // Internal edges allowed by ADR-0007 decision 1 (with ADR-0005): the core takes the
    // abstractions; an add-on takes the core and the abstractions it wires through; the
    // abstractions take nothing. A feature package referenced by another feature package
    // breaks the one-rule package choice, so the set is exact, not a supertype.
    private static readonly Dictionary<string, string[]> AllowedProjectReferences = new(StringComparer.Ordinal)
    {
        ["CredProx"] = ["CredProx.Abstractions"],
        ["CredProx.Abstractions"] = [],
        ["CredProx.Identity"] = ["CredProx", "CredProx.Abstractions"],
        ["CredProx.Azure"] = ["CredProx"],
        ["CredProx.Operations"] = ["CredProx", "CredProx.Abstractions"],
        ["CredProx.Testing"] = ["CredProx", "CredProx.Abstractions"],
    };

    public static TheoryData<string> TheSixPackages()
    {
        var data = new TheoryData<string>();
        foreach (var package in OutsideLibraries.Keys)
        {
            data.Add(package);
        }
        return data;
    }

    private static string PackageDirectory(string package) =>
        Path.Combine(RepoRoot(), "src", package);

    private static XDocument ReadProject(string package) =>
        XDocument.Load(Path.Combine(PackageDirectory(package), package + ".csproj"));

    // Package ids keep their dots - a package reference is its nuspec id verbatim.
    private static HashSet<string> PackageIncludeNames(XDocument project) =>
        project.Descendants("PackageReference")
            .Select(e => (string?)e.Attribute("Include") ?? string.Empty)
            .Where(name => name.Length > 0)
            .ToHashSet(StringComparer.Ordinal);

    // Project references are paths with MSBuild's backslash separators, which Path does not
    // split on Linux; take the segment after the last separator and drop ".csproj".
    private static HashSet<string> ProjectIncludeNames(XDocument project) =>
        project.Descendants("ProjectReference")
            .Select(e => (string?)e.Attribute("Include") ?? string.Empty)
            .Where(name => name.Length > 0)
            .Select(name => name.Split(['\\', '/'])[^1])
            .Select(name => name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                ? name[..^".csproj".Length]
                : name)
            .ToHashSet(StringComparer.Ordinal);

    [Theory]
    [MemberData(nameof(TheSixPackages))]
    public void EachPackage_PinsExactlyItsOutsideDependencies(string package)
    {
        var referenced = PackageIncludeNames(ReadProject(package));
        var expected = OutsideLibraries[package].Concat(InFrameworkReferences[package]).ToHashSet(StringComparer.Ordinal);
        Assert.True(expected.SetEquals(referenced),
            $"'{package}' PackageReference set drifted from the ADR-0007 table: expected [{string.Join(", ", expected.Order(StringComparer.Ordinal))}], found [{string.Join(", ", referenced.Order(StringComparer.Ordinal))}]. A package reference becomes a nuspec dependency for every consumer - move it to the package whose table row names it, or amend the ADR with the owner first.");
    }

    [Theory]
    [MemberData(nameof(TheSixPackages))]
    public void EachPackage_PinsExactlyItsAllowedProjectReferences(string package)
    {
        var referenced = ProjectIncludeNames(ReadProject(package));
        var expected = AllowedProjectReferences[package].ToHashSet(StringComparer.Ordinal);
        Assert.True(expected.SetEquals(referenced),
            $"'{package}' ProjectReference set drifted from ADR-0007 decision 1: expected [{string.Join(", ", expected.Order(StringComparer.Ordinal))}], found [{string.Join(", ", referenced.Order(StringComparer.Ordinal))}]. Feature packages never depend on another feature package.");
    }

    [Fact]
    public void TheSrcTreeShipsExactlyTheSixPinnedPackages()
    {
        var onDisk = Directory.EnumerateDirectories(Path.Combine(RepoRoot(), "src"))
            .Where(dir => File.Exists(Path.Combine(dir, Path.GetFileName(dir) + ".csproj")))
            .Select(Path.GetFileName)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(onDisk.SetEquals(OutsideLibraries.Keys),
            $"src/ holds [{string.Join(", ", onDisk.Order(StringComparer.Ordinal))}] but the ADR-0007 pin table lists [{string.Join(", ", OutsideLibraries.Keys.Order(StringComparer.Ordinal))}]; a seventh package needs the owner's ADR first.");
    }

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
