using BenchmarkDotNet.Running;

// Plan §7: tests/CredProx.Benchmarks (BenchmarkDotNet). Run a filter by name, e.g.
//   dotnet run -c Release --project tests/CredProx.Benchmarks -- TokenCache
// CI only builds this project (it is in the solution); running benches belongs to a
// dedicated machine, not a shared runner.
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
