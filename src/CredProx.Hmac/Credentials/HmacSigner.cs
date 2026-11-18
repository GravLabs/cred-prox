using System.Security.Cryptography;
using System.Text;

namespace CredProx;

/// <summary>
/// Builds the canonical string from the final outbound request form and computes the
/// signature. Pure with respect to the inputs it is given (request parts, body, timestamp)
/// so the semantics are testable without the YARP pipeline; the independent reference
/// verifiers in the tests re-implement the same layouts from their documented forms.
/// </summary>
internal static class HmacSigner
{
    /// <summary>
    /// Parses a component token. Returns <see langword="false"/> for anything unrecognized
    /// (the startup validator rejects those; the signer stays defensive anyway).
    /// </summary>
    public static bool TryParseComponent(string token, out HmacComponentKind kind, out string argument)
    {
        argument = string.Empty;
        switch (token.Trim().ToLowerInvariant())
        {
            case "method":
                kind = HmacComponentKind.Method;
                return true;
            case "path":
                kind = HmacComponentKind.Path;
                return true;
            case "query":
                kind = HmacComponentKind.Query;
                return true;
            case "timestamp":
                kind = HmacComponentKind.Timestamp;
                return true;
            case "bodyhash":
                kind = HmacComponentKind.BodyHash;
                return true;
            default:
                if (token.StartsWith("header:", StringComparison.OrdinalIgnoreCase))
                {
                    argument = token["header:".Length..].Trim();
                    kind = HmacComponentKind.Header;
                    return argument.Length > 0;
                }

                kind = HmacComponentKind.Method;
                return false;
        }
    }

    // path/query come from CredProxRequestState.OutboundPath/OutboundQuery: on the live
    // pipeline RequestUri is still null while features run (YARP assembles it after the
    // last transform), so the state carries the final form. They fall back to the request
    // for direct callers and tests.
    public static string BuildCanonicalString(
        IReadOnlyList<(HmacComponentKind Kind, string Argument)> components,
        HttpRequestMessage request,
        byte[] body,
        HmacOptions options,
        DateTimeOffset now,
        string? path = null,
        string? query = null)
    {
        var parts = new List<string>(components.Count);
        foreach (var (kind, argument) in components)
        {
            parts.Add(kind switch
            {
                HmacComponentKind.Method => request.Method.Method,
                HmacComponentKind.Path => path ?? request.RequestUri?.AbsolutePath ?? string.Empty,
                HmacComponentKind.Query => (query ?? request.RequestUri?.Query ?? string.Empty).TrimStart('?'),
                HmacComponentKind.Timestamp => FormatTimestamp(now, options.TimestampFormat),
                HmacComponentKind.BodyHash => ConvertHash(body, options),
                HmacComponentKind.Header => ResolveHeader(request, argument),
                _ => string.Empty,
            });
        }

        return string.Join(options.Separator, parts);
    }

    /// <summary>
    /// Header values as the upstream will see them: request headers first, then content
    /// headers — a vendor verifier reads the merged set, so <c>header:Content-Type</c>
    /// must resolve to the content header.
    /// </summary>
    private static string ResolveHeader(HttpRequestMessage request, string name)
    {
        if (request.Headers.TryGetValues(name, out var values))
        {
            return string.Join(",", values);
        }

        if (request.Content?.Headers.TryGetValues(name, out var contentValues) == true)
        {
            return string.Join(",", contentValues);
        }

        return string.Empty;
    }

    public static string Sign(string canonicalString, string key, HmacOptions options)
    {
        var data = Encoding.UTF8.GetBytes(canonicalString);
        var keyBytes = Encoding.UTF8.GetBytes(key);

        byte[] signature = options.Algorithm switch
        {
            HmacAlgorithm.SHA256 => HMACSHA256.HashData(keyBytes, data),
            HmacAlgorithm.SHA384 => HMACSHA384.HashData(keyBytes, data),
            HmacAlgorithm.SHA512 => HMACSHA512.HashData(keyBytes, data),
            _ => throw new InvalidOperationException($"Unsupported HMAC algorithm '{options.Algorithm}'."),
        };

        return Encode(signature, options.Encoding);
    }

    public static string FormatTimestamp(DateTimeOffset now, HmacTimestampFormat format) =>
        format switch
        {
            HmacTimestampFormat.UnixSeconds => now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            HmacTimestampFormat.Iso8601Utc => now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture),
            _ => throw new InvalidOperationException($"Unsupported timestamp format '{format}'."),
        };

    private static string ConvertHash(byte[] body, HmacOptions options)
    {
        byte[] hash = options.Algorithm switch
        {
            HmacAlgorithm.SHA256 => SHA256.HashData(body),
            HmacAlgorithm.SHA384 => SHA384.HashData(body),
            HmacAlgorithm.SHA512 => SHA512.HashData(body),
            _ => throw new InvalidOperationException($"Unsupported HMAC algorithm '{options.Algorithm}'."),
        };

        return Encode(hash, options.Encoding);
    }

    private static string Encode(byte[] bytes, HmacSignatureEncoding encoding) => encoding switch
    {
        HmacSignatureEncoding.HexLower => Convert.ToHexString(bytes).ToLowerInvariant(),
        HmacSignatureEncoding.HexUpper => Convert.ToHexString(bytes),
        HmacSignatureEncoding.Base64 => Convert.ToBase64String(bytes),
        _ => throw new InvalidOperationException($"Unsupported signature encoding '{encoding}'."),
    };
}

internal enum HmacComponentKind
{
    Method,
    Path,
    Query,
    Timestamp,
    BodyHash,
    Header,
}
