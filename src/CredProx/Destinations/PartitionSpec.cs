namespace CredProx;

/// <summary>
/// Parses a partition spec (<c>docs/credprox-plan.md</c> §3.2: <c>header:X-API-Env</c>)
/// into its scheme and argument at the first <c>:</c>. The scheme selects the
/// <see cref="Abstractions.IPartitionSourceFactory"/>; the argument is handed to it.
/// </summary>
internal static class PartitionSpec
{
    /// <summary>
    /// Splits <paramref name="spec"/> at the first <c>:</c>.
    /// </summary>
    /// <param name="spec">The configured value, for example <c>header:X-API-Env</c>.</param>
    /// <param name="scheme">The scheme part, trimmed; empty when the spec has no non-empty scheme.</param>
    /// <param name="argument">The argument part (everything after the first <c>:</c>), never null.</param>
    /// <returns><see langword="true"/> when the spec has a non-empty scheme and a separator.</returns>
    public static bool TryParse(string? spec, out string scheme, out string argument)
    {
        scheme = string.Empty;
        argument = string.Empty;

        if (string.IsNullOrWhiteSpace(spec))
        {
            return false;
        }

        var separator = spec.IndexOf(':');
        if (separator <= 0)
        {
            return false;
        }

        scheme = spec[..separator].Trim();
        argument = spec[(separator + 1)..];
        return scheme.Length > 0;
    }
}
