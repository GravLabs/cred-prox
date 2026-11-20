using System.Diagnostics;
using System.Text.Json;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The packed <c>releaseNotes</c> is plain text on the nuget.org package page and the documented
/// field is a description of this release, so it leads with the version. MSBuild expands a property
/// at assignment: a <c>PackageReleaseNotes</c> declared before <c>build/Version.props</c> is imported
/// silently ships "Changes in :" — the M44 must-fix proved it on packed bytes, and nothing that ran
/// green could see it. This guard evaluates both properties for every packable project the same way
/// a pack does and pins that the version actually lands in the string.
/// </summary>
public sealed class PackageReleaseNotesGuardTests
{
    [Fact]
    public void EveryPackableProject_ReleaseNotesLeadWithTheVersion()
    {
        var root = RepoRoot();
        var projects = Directory.EnumerateDirectories(Path.Combine(root, "src"))
            .Select(d => Path.Combine(d, Path.GetFileName(d) + ".csproj"))
            .Where(File.Exists)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(projects);

        foreach (var project in projects)
        {
            var (version, releaseNotes) = EvaluateVersionAndReleaseNotes(project);
            var name = Path.GetFileNameWithoutExtension(project);
            Assert.False(string.IsNullOrEmpty(version), $"{name}: no Version evaluated");
            Assert.StartsWith("Changes in ", releaseNotes);
            Assert.Contains(version, releaseNotes);
        }
    }

    private static (string Version, string ReleaseNotes) EvaluateVersionAndReleaseNotes(string project)
    {
        var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
        var psi = new ProcessStartInfo(dotnet)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(project)!,
        };
        psi.ArgumentList.Add("msbuild");
        psi.ArgumentList.Add(project);
        psi.ArgumentList.Add("-getProperty:Version");
        psi.ArgumentList.Add("-getProperty:PackageReleaseNotes");
        using var process = Process.Start(psi);
        Assert.NotNull(process);
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"msbuild failed for {project}: {stderr}");

        using var document = JsonDocument.Parse(stdout);
        var properties = document.RootElement.GetProperty("Properties");
        return (
            properties.GetProperty("Version").GetString() ?? string.Empty,
            properties.GetProperty("PackageReleaseNotes").GetString() ?? string.Empty);
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
