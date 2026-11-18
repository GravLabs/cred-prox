using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace CredProx.SampleSmokes;

// The host ports each sample claims in the files this reads: compose host mappings
// (samples/**/docker-compose.yml), localhost URLs in a sample's appsettings*.json,
// and localhost literals in tests/CredProx.SampleSmokes/*Fixture.cs. A port claimed
// in any other file — wiremock mapping JSON, sample scripts, stub sources, READMEs —
// is invisible here, and so to both consumers: PortUniquenessTests (every claimed
// port has exactly one owning sample) and EnsureFreeFor (a fixture fails at once
// with a named diagnostic instead of losing a whole collection to a bind error).
public static class SmokePorts
{
    public sealed record Claim(int Port, string Sample, string Source);

    public static IReadOnlyList<Claim> AllClaims()
    {
        var repoRoot = LocateRepoRoot();
        var claims = new List<Claim>();

        var mapping = new Regex(@"^-\s*""?(?<host>\d{2,5}):(?<port>\d{2,5})""?\s*$");
        var literal = new Regex(@"localhost:(?<port>\d{2,5})(?!\d)");

        foreach (var sampleDir in Directory.EnumerateDirectories(Path.Combine(repoRoot, "samples")))
        {
            var sample = Path.GetFileName(sampleDir);

            foreach (var compose in Directory.EnumerateFiles(sampleDir, "docker-compose.yml", SearchOption.AllDirectories)
                         .Where(p => !InBuildOutput(p)))
            {
                foreach (var raw in File.ReadAllLines(compose))
                {
                    var m = mapping.Match(raw.Trim());
                    if (m.Success)
                    {
                        claims.Add(new Claim(int.Parse(m.Groups["host"].Value), sample, compose));
                    }
                }
            }

            foreach (var json in Directory.EnumerateFiles(sampleDir, "appsettings*.json", SearchOption.AllDirectories)
                         .Where(p => !InBuildOutput(p)))
            {
                foreach (Match m in literal.Matches(File.ReadAllText(json)))
                {
                    claims.Add(new Claim(int.Parse(m.Groups["port"].Value), sample, json));
                }
            }
        }

        var smokesDir = Path.Combine(repoRoot, "tests", "CredProx.SampleSmokes");
        foreach (var fixture in Directory.EnumerateFiles(smokesDir, "*Fixture.cs"))
        {
            var sample = Path.GetFileName(fixture)[..^"Fixture.cs".Length];
            foreach (Match m in literal.Matches(File.ReadAllText(fixture)))
            {
                claims.Add(new Claim(int.Parse(m.Groups["port"].Value), sample, fixture));
            }
        }

        return claims;
    }

    // Fail fast, before any resource is created: if this sample's port is already
    // bound, name it and whoever appears to hold it. A double-booked port otherwise
    // surfaces as a compose bind error or a refused connection many lines later.
    // Compose-backed fixtures call this right after their own `compose down`, so a
    // stack this same sample left behind clears its ports instead of failing the run;
    // what the check then catches is a foreign holder — another sample's stack, or a
    // stray process.
    public static void EnsureFreeFor(string sample)
    {
        var claims = AllClaims();
        var mine = claims
            .Where(c => c.Sample.Equals(sample, StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Port)
            .Distinct()
            .Order()
            .ToList();
        if (mine.Count == 0)
        {
            return;
        }

        var bound = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
            .Select(l => l.Port)
            .ToHashSet();

        var blocked = mine.Where(bound.Contains).ToList();
        if (blocked.Count == 0)
        {
            return;
        }

        var port = blocked[0];
        var other = claims.FirstOrDefault(c => c.Port == port && !c.Sample.Equals(sample, StringComparison.OrdinalIgnoreCase));
        throw new InvalidOperationException(
            $"{sample} cannot start: host port {port} is already bound. " +
            (other is null
                ? "No other sample claims this port — it is most likely a container or process left behind by an earlier interrupted run."
                : $"The other sample claiming port {port} is {other.Sample} (see {Path.GetFileName(other.Source)}); nothing else should bind it."));
    }

    private static bool InBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") ||
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}");

    private static string LocateRepoRoot()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        return string.Join(Path.DirectorySeparatorChar, parts.Take(binIndex - 2));
    }
}
