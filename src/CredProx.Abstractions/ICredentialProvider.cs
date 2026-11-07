using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Produces the credential value to attach to an outbound request. Built-ins include
/// OAuth client credentials, login exchange and static keys; plugin authors register
/// their own types explicitly.
/// </summary>
/// <typeparam name="TOptions">
/// The typed options for this credential type. The core binds them from the matching
/// <c>CredProx:Credentials:&lt;name&gt;</c> section and runs validation at startup.
/// </typeparam>
[Experimental("CREDPROX001")]
public interface ICredentialProvider<TOptions>
    where TOptions : class
{
    /// <summary>
    /// The credential type name used in configuration, for example
    /// <c>OAuthClientCredentials</c>.
    /// </summary>
    string Type { get; }

    /// <summary>
    /// Produces the credential value to attach, obtaining and caching tokens as needed
    /// (typically through <see cref="ITokenCache"/>).
    /// </summary>
    /// <param name="options">The validated options bound for the credential being used.</param>
    /// <param name="secrets">
    /// An accessor scoped to this credential's configuration; secrets outside it cannot
    /// be resolved.
    /// </param>
    /// <param name="context">
    /// The per-request context: the credential's configured name (token-cache key) and the
    /// request's partition value (per-partition secrets and endpoints).
    /// </param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="InvalidOperationException">
    /// The credential cannot be obtained. The core turns this into a
    /// <c>credprox.credential_unavailable</c> response and does not forward the request.
    /// </exception>
    ValueTask<string> GetCredentialAsync(
        TOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken);
}
