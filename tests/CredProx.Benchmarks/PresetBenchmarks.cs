using BenchmarkDotNet.Attributes;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx.Benchmarks;

/// <summary>
/// Preset composition (plan §3 "Vendor presets"): <see cref="PresetConfiguration.Compose"/>
/// runs on every registry bind and rebind, so its cost is the cost of a configuration
/// reload with a realistic fleet — 20 credentials, 3 of them preset-backed. The
/// no-preset case is the baseline: it must stay near free (same instance returned).
/// </summary>
[MemoryDiagnoser]
public class PresetBenchmarks
{
    private IConfiguration _withPresets = null!;
    private IConfiguration _withoutPresets = null!;
    private IPresetSource[] _sources = null!;

    [GlobalSetup]
    public void Setup()
    {
        var withPresets = new Dictionary<string, string?>();
        var withoutPresets = new Dictionary<string, string?>();
        for (var i = 0; i < 20; i++)
        {
            withoutPresets[$"CredProx:Credentials:cred-{i}:Type"] = "StaticKey";
            withoutPresets[$"CredProx:Credentials:cred-{i}:Name"] = "X-Api-Key";
            withoutPresets[$"CredProx:Credentials:cred-{i}:Secret"] = $"secret:key-{i}";

            withPresets[$"CredProx:Credentials:cred-{i}:Type"] = "StaticKey";
            withPresets[$"CredProx:Credentials:cred-{i}:Name"] = "X-Api-Key";
            withPresets[$"CredProx:Credentials:cred-{i}:Secret"] = $"secret:key-{i}";
        }

        // Host-defined presets under CredProx:Presets (ConfigurationPresetSource) — the
        // only preset shape the library ships since 0.4.0.
        withPresets["CredProx:Presets:oauth-a:Type"] = "OAuthClientCredentials";
        withPresets["CredProx:Presets:oauth-a:TokenEndpoint"] = "https://accounts.acme.example/token";
        withPresets["CredProx:Presets:oauth-a:ClientAuthentication"] = "BasicHeader";
        withPresets["CredProx:Presets:oauth-a:ClientSecret"] = "secret:acme-a-secret";
        withPresets["CredProx:Presets:oauth-b:Type"] = "OAuthClientCredentials";
        withPresets["CredProx:Presets:oauth-b:TokenEndpoint"] = "https://accounts.contoso.example/token";
        withPresets["CredProx:Presets:oauth-b:ClientSecret"] = "secret:contoso-b-secret";
        withPresets["CredProx:Presets:jwt-c:Type"] = "JwtAssertion";
        withPresets["CredProx:Presets:jwt-c:Algorithm"] = "RS256";
        withPresets["CredProx:Presets:jwt-c:SigningKey"] = "secret:jwt-c-key";
        withPresets["CredProx:Presets:jwt-c:Audience"] = "https://api.example";
        withPresets["CredProx:Presets:jwt-c:Exchange"] = "BearerExchange";

        withPresets["CredProx:Credentials:acme:Preset"] = "oauth-a";
        withPresets["CredProx:Credentials:acme:ClientId"] = "client-id";
        withPresets["CredProx:Credentials:contoso:Preset"] = "oauth-b";
        withPresets["CredProx:Credentials:contoso:ClientId"] = "client-id";
        withPresets["CredProx:Credentials:jwtc:Preset"] = "jwt-c";
        withPresets["CredProx:Credentials:jwtc:Issuer"] = "app-id";

        _withPresets = new ConfigurationBuilder().AddInMemoryCollection(withPresets).Build();
        _withoutPresets = new ConfigurationBuilder().AddInMemoryCollection(withoutPresets).Build();
        _sources = [new ConfigurationPresetSource(_withPresets)];
    }

    /// <summary>No credential references a preset: Compose returns the same instance.</summary>
    [Benchmark(Baseline = true)]
    public IConfiguration NoPresets() => PresetConfiguration.Compose(_withoutPresets, _sources, []);

    /// <summary>Three preset-backed credentials layered under twenty plain ones.</summary>
    [Benchmark]
    public IConfiguration WithPresets() => PresetConfiguration.Compose(_withPresets, _sources, []);
}
