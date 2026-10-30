using BenchmarkDotNet.Attributes;
using CredProx;
using Microsoft.Extensions.Configuration;

namespace CredProx.Benchmarks;

/// <summary>
/// Per-request destination work (plan §3.3): the registry lookup a route's
/// <c>CredProx.Destination</c> metadata resolves to, and the address-template expansion
/// for an already-admitted partition. Allow-list admission itself lives in the partition
/// source and needs an <c>HttpContext</c>; it is covered by the security property tests,
/// not by these microbenchmarks.
/// </summary>
[MemoryDiagnoser]
public class DestinationBenchmarks
{
    private DestinationRegistry _registry = null!;
    private DestinationEntry _entry = null!;

    [GlobalSetup]
    public void Setup()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Destinations:acme:Template"] = "https://{partition}.acme.example/v1",
                ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
                ["CredProx:Destinations:acme:Allowed:0"] = "prod",
                ["CredProx:Destinations:acme:Allowed:1"] = "staging",
                ["CredProx:Destinations:echo:Address"] = "https://postman-echo.com",
            })
            .Build();

        _registry = new DestinationBinder(configuration, [new HeaderPartitionSourceFactory()]).Bind();
        _entry = _registry.Get("acme");
    }

    /// <summary>Registry name lookup, as the request pipeline resolves route metadata.</summary>
    [Benchmark(Baseline = true)]
    public bool Lookup() => _registry.TryGet("acme", out _);

    /// <summary>Template expansion for a partition that passed the allow-list.</summary>
    [Benchmark]
    public string Expand() => _entry.ResolvePrefix("prod");
}
