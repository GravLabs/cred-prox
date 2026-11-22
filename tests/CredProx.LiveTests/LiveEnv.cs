namespace CredProx.LiveTests;

// The machine-local secret contract shared by every live vendor (plan M46, owner
// decision 2026-11-22): ONE central file ~/.config/credprox-live/live.env,
// owner-only mode (exactly 600), holding every vendor's variables. Single-line
// KEY=VALUE entries; # lines are comments. A vendor's probe returns ONLY its own
// variables — another vendor's line in the central file never enters its values.
// A stale per-vendor file next to the central one is noticed by name as ignored,
// never read. Values never enter the repository and are never echoed by the
// scaffold — every diagnostic names files, modes and variable names only. A
// missing file, a loose mode or a missing variable is a SKIP with the names
// listed, never a pass.
public sealed record LiveEnvResult(
    bool Available,
    string DisplayPath,
    IReadOnlyList<string> Problems,
    IReadOnlyDictionary<string, string> Values,
    IReadOnlyList<string> Notices)
{
    public string SkipReason => "SKIP (live): " + string.Join("; ", Problems);
}

public static class LiveEnv
{
    // The one central file every live vendor reads (per-vendor files are dead:
    // a stale one is only ever named as ignored, never opened for values).
    public const string CentralDisplay = "~/.config/credprox-live/live.env";

    public static string CentralFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".config",
        "credprox-live",
        "live.env");

    // path is overridable for the contract's own offline tests; live runs leave it null.
    // Values are filtered to requiredKeys: another vendor's line in the central file
    // never enters this vendor's dictionary (vendor isolation).
    public static LiveEnvResult Probe(string vendor, IReadOnlyList<string> requiredKeys, string? path = null)
    {
        path ??= CentralFilePath;
        var display = CentralDisplay;
        var problems = new List<string>();
        var notices = new List<string>();
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!File.Exists(path))
        {
            problems.Add($"live env file '{display}' does not exist");
            problems.Add($"required variables: {string.Join(", ", requiredKeys)}");
            return new LiveEnvResult(false, display, problems, values, notices);
        }

        var mode = File.GetUnixFileMode(path);
        if (mode != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            problems.Add($"live env file '{display}' is mode {OctalMode(mode)}, must be exactly 600");
        }

        // A stale per-vendor file sits beside the central file it replaced: named
        // once, said to be ignored, its content never read nor echoed.
        var stale = Path.Combine(Path.GetDirectoryName(path)!, vendor + ".env");
        if (File.Exists(stale))
        {
            notices.Add(
                $"per-vendor file '~/.config/credprox-live/{vendor}.env' exists and is IGNORED " +
                $"(every vendor reads {display})");
        }

        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var eq = line.IndexOf('=');
            if (eq <= 0)
            {
                problems.Add($"unparseable line in '{display}' (expected KEY=VALUE)");
                continue;
            }

            var key = line[..eq].Trim();
            if (!requiredKeys.Contains(key, StringComparer.Ordinal))
            {
                continue;
            }

            values[key] = line[(eq + 1)..].Trim();
        }

        var missing = requiredKeys.Where(key => !values.ContainsKey(key)).ToList();
        if (missing.Count > 0)
        {
            problems.Add($"missing variables: {string.Join(", ", missing)}");
        }

        return new LiveEnvResult(problems.Count == 0, display, problems, values, notices);
    }

    private static string OctalMode(UnixFileMode mode) => Convert.ToString((int)mode, 8).PadLeft(3, '0');
}

// The GitHubApp vendor's contract: App id and installation id are numeric; the app's
// private key PEM travels base64-encoded on one line so the env file stays a flat
// KEY=VALUE format. GitHub's downloaded key (PKCS#1) is what the library imports via
// ImportFromPem, so no conversion step is needed.
public static class GitHubAppEnv
{
    public const string Vendor = "githubapp";

    public static readonly IReadOnlyList<string> RequiredKeys = ["APP_ID", "INSTALLATION_ID", "PRIVATE_KEY_BASE64"];

    public static LiveEnvResult Probe() => LiveEnv.Probe(Vendor, RequiredKeys);

    public static string TokenEndpointFor(string installationId) =>
        $"https://api.github.com/app/installations/{installationId}/access_tokens";

    // Shape problems only — names and reasons, never values.
    public static IReadOnlyList<string> ValueProblems(IReadOnlyDictionary<string, string> values)
    {
        var problems = new List<string>();
        foreach (var name in new[] { "APP_ID", "INSTALLATION_ID" })
        {
            if (values.TryGetValue(name, out var value) && (value.Length == 0 || !value.All(char.IsAsciiDigit)))
            {
                problems.Add($"{name} must be digits only (a GitHub {name.Replace('_', ' ').ToLowerInvariant()})");
            }
        }

        if (values.TryGetValue("PRIVATE_KEY_BASE64", out var encoded))
        {
            try
            {
                var pem = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                if (!pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
                {
                    problems.Add("PRIVATE_KEY_BASE64 does not decode to a private key PEM");
                }
            }
            catch (FormatException)
            {
                problems.Add("PRIVATE_KEY_BASE64 is not base64");
            }
        }

        return problems;
    }

    public static string PrivateKeyPem(IReadOnlyDictionary<string, string> values) =>
        System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(values["PRIVATE_KEY_BASE64"]));
}
