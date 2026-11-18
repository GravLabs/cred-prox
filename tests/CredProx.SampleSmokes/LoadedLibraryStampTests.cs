using System.Diagnostics;
using System.Reflection;
using Xunit;

namespace CredProx.SampleSmokes;

// Provenance guard running in every sample smoke run: the smokes must drive library
// bytes built from the SHA under test. NuGet serves an exact-version cache hit for the
// version under test without re-checking it against a feed, so stale library bytes can ride
// through every smoke unnoticed — this cell asserts, on by default, that every
// CredProx*.dll in the test host's bin and in every sample's bin carries THIS checkout's
// commit in its InformationalVersion stamp, and that every sample bin exists for the run
// configuration. The test host's core entry is read from the loaded assembly's attribute;
// every other assembly is read from the binaries the fixtures exec as separate processes.
// The stamp names a commit — it cannot tell
// committed bytes from uncommitted edits at that commit, so the remedy is always to
// pack from a clean tree.
public sealed class LoadedLibraryStampTests
{
    [Fact]
    [Trait("Sample", "Stamp")]
    public void EveryBinCarriesTheCandidateLibraryBytes()
    {
        // The config segment of this assembly's own bin is the config the smokes run.
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 0 && binIndex + 1 < parts.Length, $"unexpected test location '{own}'");
        var config = parts[binIndex + 1];

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
        var head = GitHead(repoRoot);

        var ownDll = Path.Combine(own, "CredProx.dll");
        Assert.True(File.Exists(ownDll), $"{ownDll} is missing — this host never resolved the CredProx package");

        // One bin per sample directory in the run configuration: a bin that is absent must
        // fail the gate, not shrink it — a sample whose bin was never built is exactly the
        // run that proves nothing about its library bytes.
        var expectedBins = Directory.EnumerateDirectories(Path.Combine(repoRoot, "samples"))
            .OrderBy(d => d, StringComparer.Ordinal)
            .Select(d => Path.Combine(d, "bin", config, "net10.0"))
            .ToList();
        var missingBins = expectedBins.Where(b => !Directory.Exists(b)).ToList();
        Assert.True(missingBins.Count == 0,
            $"the stamp gate expects one {config} bin per sample directory ({expectedBins.Count}) but did not find: " +
            string.Join(", ", missingBins.Select(b => Path.GetRelativePath(repoRoot, b))) +
            " — build the solution so every sample carries its libraries, then re-run");

        // Every CredProx assembly in every bin, not just CredProx.dll: an add-on package can
        // ride stale while the core is fresh. The revision stamp is repo-wide, so no
        // CredProx*.dll needs excluding.
        var stamps = new List<(string Dll, string Stamp)> { (ownDll, ReadLoadedStamp(ownDll)) };
        stamps.AddRange(Directory.EnumerateFiles(own, "CredProx*.dll")
            .Where(p => !string.Equals(p, ownDll, StringComparison.Ordinal))
            .OrderBy(p => p, StringComparer.Ordinal)
            .Select(p => (p, ReadEmbeddedStamp(p))));
        foreach (var bin in expectedBins)
        {
            stamps.AddRange(Directory.EnumerateFiles(bin, "CredProx*.dll")
                .OrderBy(p => p, StringComparer.Ordinal)
                .Select(p => (p, ReadEmbeddedStamp(p))));
        }
        foreach (var (dll, stamp) in stamps)
        {
            Console.WriteLine($"CREDPROX_STAMP {Path.GetRelativePath(repoRoot, dll)} = {stamp}");
        }

        var wrong = stamps
            .Where(entry => !CarriesCommit(entry.Stamp, head))
            .Select(entry => $"{Path.GetRelativePath(repoRoot, entry.Dll)}: {entry.Stamp}")
            .ToList();
        Assert.True(wrong.Count == 0,
            $"smokes would run against CredProx bytes built from another commit (this checkout is {head}):\n  " +
            string.Join("\n  ", wrong) +
            $"\n  remedy — from a CLEAN tree at {head}, pack into the local feed: " +
            "for p in src/*/; do dotnet pack \"$p\" -c Release -o artifacts/packages; done" +
            "\n  then evict the exact-version cache it rode in on: rm -rf ~/.nuget/packages/credprox*" +
            "\n  (a cache hit is never re-checked against a feed; the stamp names a commit, not a clean pack tree)");
    }

    private static string GitHead(string repoRoot)
    {
        var psi = new ProcessStartInfo("git", "rev-parse HEAD")
        {
            WorkingDirectory = repoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start git in '{repoRoot}'");
        var output = process.StandardOutput.ReadToEnd().Trim();
        var error = process.StandardError.ReadToEnd().Trim();
        process.WaitForExit();
        Assert.True(
            process.ExitCode == 0 && output.Length == 40 && output.All(Uri.IsHexDigit),
            $"the stamp gate needs this checkout's commit, but 'git rev-parse HEAD' in '{repoRoot}' " +
            $"did not answer (exit {process.ExitCode}): {error}");
        return output;
    }

    private static bool CarriesCommit(string stamp, string head)
    {
        var plus = stamp.LastIndexOf('+');
        return plus >= 0 && string.Equals(stamp[(plus + 1)..], head, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadLoadedStamp(string dllPath)
    {
        // The attribute of the assembly the host actually loads — the same bytes an exec
        // would run, read straight from the loaded metadata.
        var attribute = Assembly.LoadFrom(dllPath).GetCustomAttribute<AssemblyInformationalVersionAttribute>();
        if (string.IsNullOrEmpty(attribute?.InformationalVersion))
        {
            throw new InvalidOperationException($"{dllPath} carries no InformationalVersion attribute");
        }

        return attribute.InformationalVersion;
    }

    private static string ReadEmbeddedStamp(string dllPath)
    {
        // The VERSIONINFO product version is the same InformationalVersion, read from the
        // binaries the fixtures exec as separate processes — without pulling another
        // sample's code into this process.
        var version = FileVersionInfo.GetVersionInfo(dllPath).ProductVersion;
        if (string.IsNullOrEmpty(version))
        {
            throw new InvalidOperationException($"{dllPath} carries no product version resource");
        }

        return version;
    }
}
