using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// Shared startup binding of a partition block (spec + allow-list) into a
/// <see cref="PartitionSourceBinding"/>. Used by the destination binder and the credential
/// binder so both sides of §3.2 enforce the same rules: a spec needs a registered factory,
/// and a partition that is gated needs a non-empty allow-list — an empty one would admit
/// nothing and only look like a gate.
/// </summary>
internal static class PartitionBinder
{
    /// <summary>
    /// Binds one partition block.
    /// </summary>
    /// <param name="spec">The <c>From</c>/<c>Partition</c> value, e.g. <c>header:X-API-Env</c>.</param>
    /// <param name="allowed">The configured allow-list (may be null or empty).</param>
    /// <param name="factories">The registered partition source factories.</param>
    /// <param name="owner">What declares the block, for error text, e.g. <c>destination 'cayuse'</c>.</param>
    /// <param name="binding">The bound source when successful.</param>
    /// <param name="error">The single validation error when unsuccessful.</param>
    /// <returns><see langword="true"/> when the block is absent (unpartitioned) or bound.</returns>
    public static bool TryBind(
        string? spec,
        IReadOnlyCollection<string>? allowed,
        IEnumerable<IPartitionSourceFactory> factories,
        string owner,
        out PartitionSourceBinding? binding,
        out string? error)
    {
        binding = null;
        error = null;

        var hasSpec = !string.IsNullOrWhiteSpace(spec);
        var hasAllowed = allowed is { Count: > 0 };

        if (!hasSpec && !hasAllowed)
        {
            return true; // unpartitioned
        }

        if (!hasSpec)
        {
            error = $"The {owner} declares a partition allow-list but no Partition/From source.";
            return false;
        }

        if (!hasAllowed)
        {
            error = $"The {owner} resolves a partition but declares no Allowed values.";
            return false;
        }

        if (!PartitionSpec.TryParse(spec, out var scheme, out var argument))
        {
            error = $"The {owner} partition '{spec}' is not a 'scheme:argument' spec.";
            return false;
        }

        var factory = factories.FirstOrDefault(
            f => string.Equals(f.Scheme, scheme, StringComparison.OrdinalIgnoreCase));
        if (factory is null)
        {
            var known = string.Join(", ", factories.Select(f => f.Scheme).Order(StringComparer.OrdinalIgnoreCase));
            error = $"The {owner} partition scheme '{scheme}' has no registered partition source. Registered schemes: {known}.";
            return false;
        }

        try
        {
            binding = new PartitionSourceBinding(factory.CreateSource(argument), allowed!, spec!);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            error = $"The {owner} partition '{spec}' cannot be created: {ex.Message}";
            return false;
        }
    }
}
