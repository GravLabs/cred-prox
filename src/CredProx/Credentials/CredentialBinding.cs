using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// One credential from configuration, fully bound at startup: its options, its scoped
/// secret accessor (captured by <see cref="GetCredential"/>), and the attach step derived
/// from its options. The request pipeline resolves a binding by the name in route metadata
/// <c>CredProx.Credential</c> and never needs the generic provider types again.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredentialBinding
{
    /// <summary>The credential name from configuration.</summary>
    public required string Name { get; init; }

    /// <summary>The registered credential-type name it bound to.</summary>
    public required string TypeName { get; init; }

    /// <summary>The bound, validated options (the concrete typed instance, boxed).</summary>
    public required object Options { get; init; }

    /// <summary>
    /// Obtains the credential value for a request context, through the provider with this
    /// credential's options and scoped accessor already captured.
    /// </summary>
    public required Func<CredentialRequestContext, CancellationToken, ValueTask<string>> GetCredential { get; init; }

    /// <summary>
    /// Places an obtained value on the outbound request per this credential's attachment
    /// options; <see langword="null"/> when the options declare no attachment.
    /// </summary>
    public Action<HttpRequestMessage, string>? Attach { get; init; }

    /// <summary>
    /// The credential's bound partition source with its allow-list, or
    /// <see langword="null"/> when the credential declares no <c>Partition</c> block. The
    /// attach step resolves through it, so the token-endpoint template, secret-name
    /// expansion and the cache key only ever see an admitted value (§3.4).
    /// </summary>
    public PartitionSourceBinding? PartitionSource { get; init; }

    /// <summary>
    /// The <c>CredProx:Connections</c> name this credential's token call presents a client
    /// certificate from, or <see langword="null"/>. Validated against the connection
    /// registry at startup.
    /// </summary>
    public string? ConnectionName { get; init; }
}
