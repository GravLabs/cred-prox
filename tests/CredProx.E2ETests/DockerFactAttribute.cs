using System.Diagnostics;
using Xunit;

namespace CredProx.E2ETests;

/// <summary>
/// A fact that runs only where Docker is reachable (plan §5.1: container end-to-end tests
/// run on Linux with Docker and are skipped elsewhere). The probe runs once per discovery:
/// <c>docker version</c> with a short timeout; a missing or unresponsive daemon skips the
/// test instead of failing it.
/// </summary>
public sealed class DockerFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> DockerUnavailable = new(Probe);

    /// <summary>
    /// Whether the probe found a reachable Docker daemon. Class fixtures check this too:
    /// xunit initializes class fixtures even for skipped tests, and a fixture that starts a
    /// container would fail where the test itself is only meant to skip.
    /// </summary>
    public static bool IsAvailable => DockerUnavailable.Value is null;

    public DockerFactAttribute()
    {
        if (DockerUnavailable.Value is { } reason)
        {
            Skip = reason;
        }
    }

    private static string? Probe()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("docker", "version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (process is null)
            {
                return "Docker is not available: could not start 'docker version'.";
            }

            if (!process.WaitForExit(15_000))
            {
                process.Kill(entireProcessTree: true);
                return "Docker is not available: 'docker version' timed out.";
            }

            return process.ExitCode == 0
                ? null
                : "Docker is not available: 'docker version' exited with " + process.ExitCode + ".";
        }
        catch (Exception ex)
        {
            return "Docker is not available: " + ex.Message;
        }
    }
}
