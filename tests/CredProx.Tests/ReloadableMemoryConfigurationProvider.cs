using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;

namespace CredProx.Tests;

/// <summary>
/// An in-memory configuration source whose reload can be triggered on demand, so reload
/// behaviour can be tested without file watchers.
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
    /// Fires the configuration reload token, swapping in a fresh one — the same thing a
    /// real file or Key Vault reload does under the hood.
    /// </summary>
    public void Reload() => OnReload();

    /// <summary>
    /// Removes a key outright (a reload where the key is gone, not merely emptied) —
    /// <c>Set(key, null)</c> would leave the configuration child present.
    /// </summary>
    public void Remove(string key) => Data.Remove(key);
}
