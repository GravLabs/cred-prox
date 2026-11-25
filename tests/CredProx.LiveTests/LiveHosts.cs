using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;

namespace CredProx.LiveTests;

// Host mechanics for live runs: exec the prebuilt sample dll as its own process and
// drain its stdout/stderr into strings (the same pattern the offline smokes use).
// Locating the built binaries walks up from this assembly's bin folder, so the
// configuration the tests run in is the configuration the hosts run in.
public static class LiveHosts
{
    /// <summary>A host process with its output drained into readable strings.</summary>
    public sealed class RunningHost
    {
        private readonly StringBuilder _stdout = new();
        private readonly StringBuilder _stderr = new();

        internal RunningHost(Process process)
        {
            Process = process;
            process.OutputDataReceived += (_, e) =>
            {
                lock (_stdout)
                {
                    _stdout.AppendLine(e.Data);
                }
            };
            process.ErrorDataReceived += (_, e) =>
            {
                lock (_stderr)
                {
                    _stderr.AppendLine(e.Data);
                }
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
        }

        public Process Process { get; }

        public string Stdout
        {
            get { lock (_stdout) { return _stdout.ToString(); } }
        }

        public string Stderr
        {
            get { lock (_stderr) { return _stderr.ToString(); } }
        }
    }

    public static Process Start(string bin, string dll, Dictionary<string, string> env)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = bin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(bin, dll));
        foreach (var (key, value) in env)
        {
            psi.Environment[key] = value;
        }

        return Process.Start(psi) ?? throw new InvalidOperationException($"could not start {dll}");
    }

    public static async Task WaitUntilAsync(Func<Task<bool>> probe, string failure, int seconds = 90)
    {
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (await probe())
            {
                return;
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(failure);
    }

    // Liveness-honest variant: the failure text is assembled when the wait ACTUALLY
    // fails (the plain overload's string was interpolated at call time, so a failed
    // wait dumped the stdout as it looked BEFORE the wait — the M50 live failure),
    // names the host's exit state (a dead host takes audit, metering records and the
    // exporter loop down together, and must never look like missing counts), stops
    // early once the host exited — after a short drain grace and one final probe, so
    // lines printed just before exit are not lost — and dumps both output streams
    // sanitized — an unhandled exception prints to stderr, and stderr was drained but
    // never printed.
    public static async Task WaitUntilAsync(
        Func<Task<bool>> probe,
        string what,
        RunningHost host,
        IReadOnlyCollection<string> secrets,
        int seconds = 90)
    {
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (await probe())
            {
                return;
            }

            if (host.Process.HasExited)
            {
                // Grace for the async stdout/stderr drain: the last lines a host prints
                // before exiting (final audit line, last export batch, the tail of a
                // crash message) can still be in flight when HasExited flips. One more
                // probe after a short wait, then break — a dead process prints nothing
                // further, and the failure dump below then sees those final lines too.
                await Task.Delay(250);
                if (await probe())
                {
                    return;
                }

                break;
            }

            await Task.Delay(1000);
        }

        var exit = host.Process.HasExited
            ? $"host EXITED with code {host.Process.ExitCode}"
            : "host still running (a stall or a missing record, not a crash)";
        throw new InvalidOperationException(
            $"{what} after {seconds} s; {exit}:\n"
            + "STDOUT:\n" + SecretLeakScanner.Sanitize(host.Stdout, secrets) + "\n"
            + "STDERR:\n" + SecretLeakScanner.Sanitize(host.Stderr, secrets));
    }

    // The audit-first probe must match ONE line: the caller marker rides every audit
    // line of that caller (the GET's line carries it too), and "method=POST" appears
    // on audit lines of other callers, so two separate Contains calls over the whole
    // stdout can be satisfied by two unrelated lines — a POST that never audited could
    // still flip such a probe. Pinned by LiveHostsAuditProbeTests.
    public static bool ContainsOnOneLine(string stdout, string first, string second)
    {
        foreach (var line in stdout.Split('\n'))
        {
            if (line.Contains(first, StringComparison.Ordinal)
                && line.Contains(second, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    // Read the latest console-exporter value of a counter instrument. The pinned
    // exporter (OpenTelemetry.Exporter.Console 1.15.3) prints one line per metric
    // starting "Metric Name: <instrument>" whose value line is the FIRST "Value:"
    // after it: "Value: <n>" for LongSum counters; histograms print "Value: Sum: ..."
    // there, so they return -1 instead of reading a later block. The pre-1.12
    // spelling ("Metric name:", "Metric value:") never matches 1.15.3 output at all —
    // a wait built on it is blind even on a fully healthy pipeline, which is how the
    // M50 live cell failed while the product recorded fine.
    public static long CounterValue(string stdout, string instrument)
    {
        var marker = "Metric Name: " + instrument;
        var at = stdout.LastIndexOf(marker, StringComparison.Ordinal);
        if (at < 0)
        {
            return -1;
        }

        var window = stdout[at..Math.Min(at + 1200, stdout.Length)];
        var valueAt = window.IndexOf("Value:", StringComparison.Ordinal);
        if (valueAt < 0)
        {
            return -1;
        }

        var match = Regex.Match(window[valueAt..], @"^Value:\s*(\d+)");
        return match.Success ? long.Parse(match.Groups[1].Value) : -1;
    }

    // Wait until a counter pair holds the SAME values across two consecutive reads
    // AND both values are > 0, then return that settled pair. Live cells take a
    // baseline from this, never from the first non-zero batch: the console exporter
    // prints on a cadence and a batch can still carry a finished run's remaining
    // turns, so a first-non-zero snapshot is stale the moment the next batch lands
    // (live finding 2026-11-23: baseline 484, late batch 1283, wrong cell blamed).
    // A pair containing -1 (no batch) or a zero never counts as settled; on
    // timeout the caller's named diagnostic is thrown.
    public static async Task<(long Inputs, long Outputs)> WaitTokenCountersSettled(
        Func<(long Inputs, long Outputs)> readBoth,
        int intervalMs,
        int timeoutSeconds,
        Func<string> failMessage)
    {
        var sw = Stopwatch.StartNew();
        (long Inputs, long Outputs) prev = default;
        while (sw.Elapsed.TotalSeconds < timeoutSeconds)
        {
            await Task.Delay(intervalMs);
            var now = readBoth();
            if (now.Inputs > 0 && now.Outputs > 0 && now.Inputs == prev.Inputs && now.Outputs == prev.Outputs)
            {
                return now;
            }
            prev = now;
        }
        throw new InvalidOperationException(failMessage());
    }

    // Fail fast with a named diagnostic if a port the live run needs is already
    // bound — most likely an offline smoke run or an interrupted earlier live run.
    public static void EnsurePortsFree(params int[] ports)
    {
        var bound = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
            .Select(l => l.Port)
            .ToHashSet();
        var blocked = ports.Where(bound.Contains).ToList();
        if (blocked.Count > 0)
        {
            throw new InvalidOperationException(
                $"live run cannot start: host port(s) {string.Join(", ", blocked)} already bound — " +
                "stop whatever holds them (an offline smoke run or an interrupted live run) and retry");
        }
    }

    // bin/<configuration>/net10.0 of a project under the repo root, resolved from
    // this assembly's own location and configuration.
    public static string LocateBin(string projectRelativeDir, string dllName)
    {
        var repoRoot = LocateRepoRoot();
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar).Split(Path.DirectorySeparatorChar);
        var configuration = parts[Array.IndexOf(parts, "bin") + 1];
        var bin = Path.Combine(repoRoot, projectRelativeDir, "bin", configuration, "net10.0");
        if (!File.Exists(Path.Combine(bin, dllName)))
        {
            throw new InvalidOperationException(
                $"no built {dllName} at '{bin}' — build tests/CredProx.LiveTests first");
        }

        return bin;
    }

    // DOTNET_STARTUP_HOOKS on this runtime takes the bare assembly path and enters it
    // through the global type StartupHook (a path,TypeName spelling is not parsed).
    public static string WitnessDllPath() =>
        Path.Combine(LocateBin(Path.Combine("tests", "CredProx.LiveTests", "Witness"), "CredProx.LiveWitness.dll"), "CredProx.LiveWitness.dll");

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

    // The witness file is one observation per line (miss | hit | fetch-success |
    // fetch-failure), appended by the startup hook inside the host process.
    public sealed record WitnessCounts(int Miss, int Hit, int FetchSuccess, int FetchFailure)
    {
        public static WitnessCounts FromFile(string path)
        {
            var miss = 0;
            var hit = 0;
            var fetchSuccess = 0;
            var fetchFailure = 0;
            foreach (var line in File.ReadLines(path))
            {
                switch (line.Trim())
                {
                    case "miss":
                        miss++;
                        break;
                    case "hit":
                        hit++;
                        break;
                    case "fetch-success":
                        fetchSuccess++;
                        break;
                    case "fetch-failure":
                        fetchFailure++;
                        break;
                }
            }

            return new WitnessCounts(miss, hit, fetchSuccess, fetchFailure);
        }
    }

    // The callback writes each observation synchronously before the exchange or serve
    // continues, so a short poll covers only the file-visible lag; it also fails fast
    // on an empty witness by requiring the expected shape within the window.
    public static async Task<WitnessCounts> ReadWitnessStableAsync(string path, int seconds = 15)
    {
        await WaitUntilAsync(
            () => Task.FromResult(File.Exists(path) && File.ReadLines(path).Any(line => line.Trim() == "hit")),
            $"the witness file gained no cache hit within {seconds} s — the startup hook or its meter filter is broken",
            seconds);
        return WitnessCounts.FromFile(path);
    }
}
