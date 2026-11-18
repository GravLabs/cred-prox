using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// This package's client-id rules, contributed to the core's registry validation: blank
/// and padded entries look bound but match nothing (the mapper compares verbatim), and
/// one client id listed by two callers would authenticate one Entra app as two callers —
/// registry order decides which (ADR-0004). The core runs them at host start AND on
/// every live configuration change, so drift into a refused shape cannot take effect.
/// Errors name the caller and the entry — never a token.
/// </summary>
internal sealed class CallerTokenClientIdRules : ICallerRegistryValidator
{
    public IReadOnlyList<string> Validate(IReadOnlyList<CallerRegistryEntry> callers)
    {
        var errors = new List<string>();
        var clientOwners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var caller in callers)
        {
            var callerId = caller.CallerId;
            foreach (var entry in caller.Configuration.GetSection("TokenClientIds").GetChildren())
            {
                var clientId = entry.Value;
                if (string.IsNullOrWhiteSpace(clientId))
                {
                    errors.Add($"The caller '{callerId}' has an empty TokenClientIds entry.");
                    continue;
                }

                if (!string.Equals(clientId, clientId.Trim(), StringComparison.Ordinal))
                {
                    errors.Add(
                        $"The caller '{callerId}' has a TokenClientIds entry with leading or trailing "
                        + "whitespace — client ids are matched verbatim, so a padded entry admits nobody.");
                    continue;
                }

                if (clientOwners.TryGetValue(clientId, out var owner))
                {
                    // A case-variant pair inside ONE caller is its own defect — the
                    // two-owner wording would name the same caller twice.
                    errors.Add(string.Equals(owner, callerId, StringComparison.Ordinal)
                        ? $"The client id '{clientId}' is listed twice by caller '{callerId}' (client ids collide case-insensitively within a caller)."
                        : $"The client id '{clientId}' is listed by more than one caller ('{owner}' and '{callerId}').");
                }
                else
                {
                    clientOwners[clientId] = callerId;
                }
            }
        }

        return errors;
    }
}
