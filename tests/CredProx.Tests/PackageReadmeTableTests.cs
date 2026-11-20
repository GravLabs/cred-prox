using System.Text.Json;
using System.Text.RegularExpressions;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// The core package's README ships inside the <c>CredProx</c> nupkg and is the map a
/// host reads first: every package in <c>src</c> must appear in its Packages table —
/// a package missing there is invisible to every host that never browses the
/// repository — and every package carries its own README beside its project file.
/// The JSON hero snippets in the repository README and the core package README are
/// what a first-time host copy-pastes, so they run the fail-closed startup gate here
/// (same registration path as <see cref="VendorSnippetValidationTests"/> drives for
/// docs/vendors): a hero snippet that would refuse to start fails the battery, and a
/// probe shows that gate actually bites. The adjacent C# heroes are API-shape text,
/// not config — binding those is out of scope for this gate by design.
/// </summary>
public sealed class PackageReadmeTableTests
{
    private static readonly Regex JsonBlockPattern = new(
        @"```json\r?\n(?<json>.*?)\r?\n```", RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex PlaceholderPattern = new(
        @"<([A-Za-z0-9_.\-]+)>", RegexOptions.Compiled);

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

    [Fact]
    public void EveryPackageReadme_CarriesItsInstallLine()
    {
        // M44: a first-time nuget.org user finds the install line where they read
        // about the package — the line is the convention, so it is pinned.
        var root = RepoRoot();
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(root, "src"))
                     .Where(d => Directory.EnumerateFiles(d, "*.csproj").Any())
                     .OrderBy(d => d, StringComparer.Ordinal))
        {
            var name = Path.GetFileName(dir);
            var readme = File.ReadAllText(Path.Combine(dir, "README.md"));
            Assert.Contains($"dotnet add package {name}", readme);
        }

        Assert.Contains("dotnet add package CredProx",
            File.ReadAllText(Path.Combine(root, "README.md")));
    }

    [Fact]
    public async Task HeroConfigSnippets_StartUpValidationPasses()
    {
        // One JSON block per hero README, and that block must survive the real
        // startup gate — the same refusal a host meets on boot, not a weaker mirror.
        foreach (var readme in HeroReadmes())
        {
            var entries = HeroEntries(readme);
            var config = Build(entries);
            using var provider = Register(config);
            await StartValidatorAsync(provider, config);
        }
    }

    [Fact]
    public async Task HeroConfigSnippet_GhostCredentialReference_FailsStartup()
    {
        // The gate must bite: point a route at a credential the hero never defines
        // and startup refuses, naming it. Without this probe the happy-path fact
        // could pass on a validator that was never actually engaged.
        var readme = HeroReadmes()[0];
        var entries = HeroEntries(readme);
        var routeKey = entries.Keys.Single(k =>
            Regex.IsMatch(k, @"^ReverseProxy:Routes:[^:]+:Metadata:CredProx\.Credential$"));
        entries[routeKey] = "ghost-ref";
        var config = Build(entries);
        using var provider = Register(config);
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(
            () => StartValidatorAsync(provider, config));
        Assert.Contains("ghost-ref", ex.Message);
    }

    private static string[] HeroReadmes()
    {
        var root = RepoRoot();
        return
        [
            Path.Combine(root, "README.md"),
            Path.Combine(root, "src", "CredProx", "README.md"),
        ];
    }

    private static Dictionary<string, string?> HeroEntries(string readmePath)
    {
        var block = Assert.Single(
            JsonBlockPattern.Matches(File.ReadAllText(readmePath)).Cast<Match>());

        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        using var document = JsonDocument.Parse(
            block.Groups["json"].Value,
            new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        Flatten("", document.RootElement, entries);

        // Placeholders become their own names (the docs rule: real values never ship).
        foreach (var key in entries.Keys.ToList())
        {
            if (entries[key] is string value)
            {
                entries[key] = PlaceholderPattern.Replace(value, m => m.Groups[1].Value);
            }
        }

        return entries;
    }

    private static IConfiguration Build(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();

    private static void Flatten(string prefix, JsonElement element, Dictionary<string, string?> entries)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    Flatten(prefix.Length == 0 ? property.Name : $"{prefix}:{property.Name}", property.Value, entries);
                }

                break;
            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    Flatten($"{prefix}:{index}", item, entries);
                    index++;
                }

                break;
            default:
                entries[prefix] = element.ToString();
                break;
        }
    }

    /// <summary>Registration half of the startup gate — the set a sample host runs.</summary>
    private static ServiceProvider Register(IConfiguration config)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCredProx(config);
        services.AddCredProxOAuth();
        services.AddReverseProxy().LoadFromConfig(config.GetSection("ReverseProxy")).AddCredProx(config);
        return services.BuildServiceProvider();
    }

    private static async Task StartValidatorAsync(ServiceProvider provider, IConfiguration config)
    {
        var validator = new CredProxStartupValidator(
            provider,
            provider.GetServices<IProxyConfigProvider>(),
            config,
            provider.GetRequiredService<SecretReferenceValidator>(),
            provider.GetServices<IPresetSource>(),
            NullLogger<CredProxStartupValidator>.Instance);

        await validator.StartAsync(default);
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
