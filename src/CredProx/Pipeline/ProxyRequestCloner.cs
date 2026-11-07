using System.Reflection;

namespace CredProx;

/// <summary>
/// Clones an outbound request for a retry attempt. A sent <see cref="HttpRequestMessage"/>
/// cannot be sent again, so every retry sends a clone: headers, version and the message
/// <c>Options</c> (preserving each option key's value type, so downstream handlers still
/// find their stashed state) are copied; the body comes from a buffer captured before the
/// first attempt. Shared by refresh-on-401 and the resilience adapter.
/// </summary>
internal static class ProxyRequestCloner
{
    private static readonly MethodInfo SetOptionMethod =
        typeof(HttpRequestOptions).GetMethod(nameof(HttpRequestOptions.Set))!;

    /// <summary>
    /// Clones <paramref name="request"/>. When <paramref name="body"/> is not
    /// <see langword="null"/> the clone carries those bytes as its content (with the
    /// original content headers); a request without content clones content-free.
    /// </summary>
    public static HttpRequestMessage Clone(HttpRequestMessage request, byte[]? body)
    {
        ArgumentNullException.ThrowIfNull(request);

        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
        };

        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (body is not null)
        {
            clone.Content = new ByteArrayContent(body);
            foreach (var header in request.Content!.Headers)
            {
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        CopyOptions(request, clone);
        return clone;
    }

    private static void CopyOptions(HttpRequestMessage from, HttpRequestMessage to)
    {
        foreach (var entry in from.Options)
        {
            // Re-key with the value's runtime type so a typed TryGetValue on the clone
            // still matches; the stash the credential feature writes round-trips.
            var valueType = entry.Value?.GetType() ?? typeof(object);
            var key = Activator.CreateInstance(
                typeof(HttpRequestOptionsKey<>).MakeGenericType(valueType), entry.Key)!;
            SetOptionMethod.MakeGenericMethod(valueType).Invoke(to.Options, [key, entry.Value]);
        }
    }
}
