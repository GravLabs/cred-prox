using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;

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
