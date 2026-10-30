using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.ResolveDestination"/> feature
/// (see <c>docs/credprox-plan.md</c> §3.2/§3.4): resolves the route's
/// <c>CredProx.Destination</c> entry, admits the request's partition against its
/// allow-list, and overrides the outbound address prefix with the expanded template.
/// A missing or disallowed partition answers <c>400 credprox.partition_not_allowed</c>
/// and the request is never forwarded — and because this runs before
/// <see cref="Stage.AttachCredential"/>, no token endpoint is ever called for it.
/// </summary>
/// <remarks>
/// The partition value reaches the template only through
/// <see cref="PartitionSourceBinding.ResolveAsync"/>; the template expansion itself
/// performs no validation, so the allow-list is the single gate (§3.4, M2/M3 review carry).
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class DestinationResolutionFeature : IRequestFeature
{
    private readonly DestinationRegistryProvider _registryProvider;

    /// <summary>Creates the feature over the live destination registry.</summary>
    /// <param name="registryProvider">The reload-aware destination registry.</param>
    public DestinationResolutionFeature(DestinationRegistryProvider registryProvider) =>
        _registryProvider = registryProvider ?? throw new ArgumentNullException(nameof(registryProvider));

    /// <inheritdoc />
    public Stage Stage => Stage.ResolveDestination;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return; // not running inside the CredProx transform
        }

        if (CredProxMetadata.GetRouteMetadata(context) is not { } metadata
            || !metadata.TryGetValue(CredProxMetadata.Destination, out var name)
            || string.IsNullOrEmpty(name))
        {
            return; // route uses the cluster's static destinations
        }

        var entry = _registryProvider.Current.Get(name);
        state.Destination = entry;

        if (entry.Partition is null)
        {
            state.DestinationPrefix = entry.ResolvePrefix(string.Empty);
            return;
        }

        string partition;
        try
        {
            partition = await entry.Partition.ResolveAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (PartitionNotAllowedException ex)
        {
            await state
                .AbortAsync(ex.StatusCode, ex.Code, ex.Title)
                .ConfigureAwait(false);
            return;
        }

        state.Partition = partition;
        state.DestinationPrefix = entry.ResolvePrefix(partition);
    }
}
