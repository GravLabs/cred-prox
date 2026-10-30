using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;

namespace CredProx.E2ETests;

/// <summary>
/// An in-memory configuration source whose reload can be triggered on demand, so the
/// rotation path (secret change + proxy config reload in one signal) is exercised without
/// file watchers. Same helper as in CredProx.Tests; the test projects stay independent.
/// </summary>
internal sealed class ReloadableMemoryConfigurationSource : IConfigurationSource
{
    private readonly IDictionary<string, string?> _data;

    public ReloadableMemoryConfigurationSource(IDictionary<string, string?> data) => _data = data;

    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new ReloadableMemoryConfigurationProvider(new MemoryConfigurationSource { InitialData = _data });
}

internal sealed class ReloadableMemoryConfigurationProvider : MemoryConfigurationProvider
{
    public ReloadableMemoryConfigurationProvider(MemoryConfigurationSource source)
        : base(source)
    {
    }

    /// <summary>
    /// Fires the configuration reload token — what a real file or Key Vault reload does
    /// under the hood.
    /// </summary>
    public void Reload() => OnReload();
}
