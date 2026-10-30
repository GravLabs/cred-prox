using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The per-request record of credential values the pipeline placed on the outbound
/// request (M20, plan §8.2). The attach feature registers the value it attaches; the
/// refresh-on-401 path registers the replacement value, so a reflecting response is
/// scrubbed of every token that actually went out, old and new. The URL-encoded form
/// is registered alongside the raw value: a query-placement credential reflects in its
/// encoded shape. Values stay inside this per-request object and are never logged
/// (the value-free log discipline, §3.5).
/// </summary>
internal sealed class CredProxInjectedSecrets
{
    private readonly List<string> _values = [];

    /// <summary>The registered values — raw and encoded forms — in registration order.</summary>
    public IReadOnlyList<string> Values => _values;

    /// <summary>Whether at least one value was registered — the scrubber's fast-path gate.</summary>
    public bool HasAny => _values.Count > 0;

    /// <summary>The request's registry, created on first use and published as a feature.</summary>
    public static CredProxInjectedSecrets GetOrCreate(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var features = context.Features;
        if (features.Get<CredProxInjectedSecrets>() is { } existing)
        {
            return existing;
        }

        var created = new CredProxInjectedSecrets();
        features.Set(created);
        return created;
    }

    /// <summary>Records one value that went on the wire (raw and URL-encoded forms).</summary>
    public void Register(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        AddIfNew(value);

        // Query placement embeds the Uri.EscapeDataString form in the URL; an error page
        // echoing the full request URL reflects that form, not the raw one.
        var encoded = Uri.EscapeDataString(value);
        if (encoded != value)
        {
            AddIfNew(encoded);
        }
    }

    private void AddIfNew(string value)
    {
        if (!_values.Contains(value, StringComparer.Ordinal))
        {
            _values.Add(value);
        }
    }
}
