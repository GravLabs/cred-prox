namespace CredProx;

/// <summary>
/// Applies the audit redaction rules before a record reaches any sink
/// (<c>docs/credprox-plan.md</c> §5.2: "redacted headers/JSON fields never reach the
/// sink"). Header names in the record's <c>headers</c> map are masked against the header
/// set; any nested field whose name matches the JSON-field set is masked at any depth.
/// Masking replaces the value with <see cref="Masked"/> — the name stays, the value goes.
/// </summary>
internal static class AuditRedactor
{
    /// <summary>The value a redacted field carries instead of its content.</summary>
    public const string Masked = "[redacted]";

    /// <summary>
    /// The header names masked whatever the configuration says: the credential-bearing
    /// and cookie-bearing headers. The recorder adds the configured caller-key header
    /// names to this set.
    /// </summary>
    public static readonly IReadOnlySet<string> DefaultRedactHeaders =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "WWW-Authenticate",
            "X-CredProx-Key",
        };

    /// <summary>
    /// The nested-field names masked whatever the configuration says: the shapes a
    /// credential or secret value takes when it appears as structured data.
    /// </summary>
    public static readonly IReadOnlySet<string> DefaultRedactJsonFields =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "password",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "client_secret",
            "api_key",
            "apikey",
            "certificate",
            "private_key",
        };

    /// <summary>
    /// Masks the record in place. <paramref name="redactHeaders"/> gates the entries of
    /// the <c>headers</c> map; <paramref name="redactJsonFields"/> gates any nested field
    /// name at any depth.
    /// </summary>
    public static void Redact(
        IDictionary<string, object?> fields,
        IReadOnlySet<string> redactHeaders,
        IReadOnlySet<string> redactJsonFields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        if (fields.TryGetValue("headers", out var headers) && headers is IDictionary<string, object?> headerMap)
        {
            foreach (var name in headerMap.Keys.ToArray())
            {
                if (redactHeaders.Contains(name))
                {
                    headerMap[name] = Masked;
                }
            }
        }

        Walk(fields, redactJsonFields);
    }

    private static void Walk(IDictionary<string, object?> fields, IReadOnlySet<string> redactJsonFields)
    {
        foreach (var key in fields.Keys.ToArray())
        {
            if (fields[key] is IDictionary<string, object?> nested)
            {
                foreach (var name in nested.Keys.ToArray())
                {
                    if (redactJsonFields.Contains(name))
                    {
                        nested[name] = Masked;
                    }
                }

                Walk(nested, redactJsonFields);
            }
        }
    }
}
