using System.Diagnostics.CodeAnalysis;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Perfolizer.Horology;

// Plan §7: tests/CredProx.Benchmarks (BenchmarkDotNet). Run a filter by name, e.g.
//   dotnet run -c Release --project tests/CredProx.Benchmarks -- TokenCache
// CI only builds this project (it is in the solution); running benches belongs to a
// dedicated machine, not a shared runner. See docs/benchmarks.md for the baseline
// procedure and scripts/bench-compare.sh for the regression gate.

// The measurement job is pinned here rather than left to per-class defaults: the
// committed baseline and every comparison run must execute under the identical job or
// the diff measures configuration, not code. Five warm-up plus fifteen 250 ms
// iterations is enough for a stable median and p95 on the loopback suites while
// keeping the full sweep inside a quiet window; the defaults would roughly triple
// the wall clock for no visible gain on these fast ops, and the ShortRun job is too
// thin for percentiles on a shared machine.
[ExcludeFromCodeCoverage]
public static class Program
{
    public static void Main(string[] args)
    {
        var job = Job.Default
            .WithLaunchCount(1)
            .WithWarmupCount(5)
            .WithIterationCount(15)
            .WithIterationTime(TimeInterval.FromMilliseconds(250));

        // The full JSON exporter is pinned alongside the default markdown/CSV/HTML ones:
        // the committed baseline and the comparison script both read the JSON (statistics
        // and per-iteration measurements), so every run must produce it.
        var config = ManualConfig.Create(DefaultConfig.Instance)
            .AddJob(job)
            .AddExporter(JsonExporter.Full);
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
    }
}
