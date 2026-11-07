using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Per-request context a credential provider needs beyond its bound options: the
/// credential's configured name (for the <c>(credential, partition)</c> token-cache key)
/// and the request's partition value (for per-partition secrets and endpoints; see
/// <c>docs/credprox-plan.md</c> §3.2).
/// </summary>
/// <remarks>
/// A pure data holder — no behavior. Init-only properties so later milestones can add
/// context (caller identity, route) without breaking the provider signature again.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredentialRequestContext
{
    /// <summary>
    /// The credential's name from configuration (<c>CredProx:Credentials:&lt;name&gt;</c>).
    /// Used as the token-cache key's credential component; never a secret.
    /// </summary>
    public required string CredentialName { get; init; }

    /// <summary>
    /// The partition value for this request, or <see langword="null"/> for unpartitioned
    /// credentials. Providers expand <c>{partition}</c> templates with it and use it as the
    /// token-cache key's partition component.
    /// </summary>
    public string? Partition { get; init; }

    /// <summary>
    /// The caller's inbound bearer token (the raw value of the inbound
    /// <c>Authorization</c> header, scheme stripped), populated by the core only for
    /// credentials whose options declare <c>IRequiresInboundToken</c> — delegated types
    /// such as <c>TokenExchange</c> (see <c>docs/credprox-plan.md</c> §3.6).
    /// <see langword="null"/> when the request carried none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a <c>secret</c> in the §3.5 rule-4 sense: never log it, never expand it into
    /// <c>{partition}</c> templates, never use it as a token-cache key component (it changes
    /// on every refresh — key on the validated subject instead).
    /// </para>
    /// <para>
    /// Providers must validate it before trusting any claim from it: an unvalidated claim
    /// lets an attacker forge another user's identity into a cache key.
    /// </para>
    /// </remarks>
    public string? InboundToken { get; init; }

    /// <summary>
    /// The effective token-cache partition the provider used for this request, recorded by
    /// providers whose cache key goes beyond <c>(credential, partition)</c> — for example
    /// <c>TokenExchange</c>, which keys per user subject (§3.6). The core's refresh-on-401
    /// invalidation drops <c>CachePartition ?? Partition</c>, so a downstream 401 evicts the
    /// right per-user entry. <see langword="null"/> (the default) keeps the plain
    /// <c>(credential, partition)</c> invalidation every other provider uses.
    /// </summary>
    public string? CachePartition { get; set; }
}
