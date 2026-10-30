using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The add-on <c>TokenCredential</c> provider (see <c>docs/credprox-plan.md</c> §4): wraps an
/// <c>Azure.Core.TokenCredential</c> — a managed identity, workload identity, or anything
/// else implementing the Azure.Core abstraction. The token is cached per
/// <c>(credential, partition)</c> through <see cref="ITokenCache"/> until its
/// <see cref="AccessToken.ExpiresOn"/>. Failures surface as
/// <see cref="InvalidOperationException"/> naming only the exception type — credential
/// pipeline errors can echo request fragments, so messages never carry them.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class AzureTokenCredentialProvider : ICredentialProvider<TokenCredentialOptions>
{
    private readonly ITokenCache _cache;
    private readonly TokenCredential _credential;

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="credential">The Azure token credential to exchange for tokens.</param>
    public AzureTokenCredentialProvider(ITokenCache cache, TokenCredential credential)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
    }

    /// <inheritdoc />
    public string Type => "TokenCredential";

    /// <inheritdoc />
    public ValueTask<string> GetCredentialAsync(
        TokenCredentialOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(context);

        return _cache.GetTokenAsync(
            context.CredentialName,
            context.Partition,
            ct => FetchAsync(context.CredentialName, options.Scope, ct),
            cancellationToken);
    }

    private async ValueTask<(string Value, DateTimeOffset ExpiresAt)> FetchAsync(
        string credentialName,
        string scope,
        CancellationToken cancellationToken)
    {
        AccessToken token;
        try
        {
            token = await _credential
                .GetTokenAsync(new TokenRequestContext([scope]), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"The Azure token credential for credential '{credentialName}' failed: {ex.GetType().Name}.", ex);
        }

        return (token.Token, token.ExpiresOn);
    }
}
