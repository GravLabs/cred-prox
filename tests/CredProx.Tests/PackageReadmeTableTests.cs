using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The core package's README ships inside the <c>CredProx</c> nupkg and is the map a
/// host reads first: every package in <c>src</c> must appear in its Packages table —
/// a package missing there is invisible to every host that never browses the
/// repository — and every package carries its own README beside its project file.
/// </summary>
public sealed class PackageReadmeTableTests
{
    [Fact]
    public void EverySrcPackage_AppearsInTheCoreReadmePackagesTable()
    {
        var root = RepoRoot();
        var packages = PackageNames(root);
        Assert.NotEmpty(packages);

        var readme = File.ReadAllText(Path.Combine(root, "src", "CredProx", "README.md"));
        var heading = readme.IndexOf("## Packages", StringComparison.Ordinal);
        Assert.True(heading >= 0, "the core README has no Packages section");
        var rest = readme[(heading + "## Packages".Length)..];
        var next = rest.IndexOf("\n## ", StringComparison.Ordinal);
        var section = next < 0 ? rest : rest[..next];

        foreach (var name in packages)
        {
            Assert.Contains($"| `{name}` |", section);
        }
    }

    [Fact]
    public void EverySrcPackage_CarriesItsOwnReadme()
    {
        var root = RepoRoot();
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(root, "src"))
                     .Where(d => Directory.EnumerateFiles(d, "*.csproj").Any())
                     .OrderBy(d => d, StringComparer.Ordinal))
        {
            Assert.True(File.Exists(Path.Combine(dir, "README.md")),
                $"package {Path.GetFileName(dir)} has no README.md beside its project file");
        }
    }

    private static List<string> PackageNames(string root) =>
        Directory.EnumerateDirectories(Path.Combine(root, "src"))
            .Where(d => Directory.EnumerateFiles(d, "*.csproj").Any())
            .Select(d => Path.GetFileName(d)!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

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
