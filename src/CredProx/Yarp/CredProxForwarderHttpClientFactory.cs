using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx;

/// <summary>
/// The CredProx <see cref="ForwarderHttpClientFactory"/> (see
/// <c>docs/credprox-plan.md</c> §3.3): applies the cluster's client certificate
/// (<c>CredProx.Connection</c> cluster metadata) and any registered
/// <see cref="IConnectionFeature"/> in <c>ConfigureHandler</c>, and composes the outbound
/// pipeline in <c>WrapHandler</c> — the refresh-on-401 handler innermost, then the
/// registered <see cref="IPipelineFeature"/> handlers in stage order (lowest stage
/// outermost).
/// </summary>
/// <remarks>
/// Not sealed: subclassing this factory is the plan's extension point (§3.3 "client
/// factory subclass") — override <c>ConfigureHandler</c>/<c>WrapHandler</c> around the
/// CredProx composition, or call <see cref="ComposePipeline"/> over a custom transport.
/// </remarks>
/// <remarks>
/// <para>
/// Certificate rotation and identity: YARP recreates a cluster's client when it next calls
/// <c>CreateClient</c>, which happens on a configuration reload. A stamp of
/// <c>(connection object, version)</c> is added to <c>CanReuseOldClient</c>, so a reload that
/// rotated the certificate rebuilds the client while an unrelated reload still reuses it.
/// The stamp holds the connection <em>object</em>, not its name: any reload that replaces the
/// connection object — a different name in the metadata, the same name repointed at a
/// different secret reference, or removal of the <c>Connection</c> metadata — changes the
/// stamp even when the new object's version collides with the old one's (a fresh connection
/// starts at version 1, so a name-only comparison could reuse a client presenting the previous
/// certificate). "No connection" and "unknown connection" are their own stamp values (a null
/// object with a sentinel version), so a cluster never keeps presenting a certificate it is no
/// longer configured for. With the configuration-backed secret source a certificate rotation
/// arrives with exactly such a reload; a standalone secret source must also signal a proxy
/// config reload for the rebuild to happen.
/// </para>
/// <para>
/// The per-connection token clients (a credential's <c>Connection</c> option) get their
/// certificate from the same connection; <see cref="IHttpClientFactory"/> recreates primary
/// handlers on their expiry, so those pick rotation up without the version stamp.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public class CredProxForwarderHttpClientFactory : ForwarderHttpClientFactory
{
    /// <summary>Stamp version for a cluster that declares no connection.</summary>
    private const long NoConnectionVersion = 0;

    /// <summary>Stamp version for a declared connection the registry does not (yet) have.</summary>
    private const long UnknownConnectionVersion = -1;

    private readonly IServiceProvider _services;
    private readonly ConcurrentDictionary<string, (ClientCertificateConnection? Connection, long Version)> _certificateStamps =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates the factory.</summary>
    /// <param name="services">Resolves the registries, features and options lazily.</param>
    public CredProxForwarderHttpClientFactory(IServiceProvider services) =>
        _services = services ?? throw new ArgumentNullException(nameof(services));

    /// <inheritdoc />
    protected override bool CanReuseOldClient(ForwarderHttpClientContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!base.CanReuseOldClient(context))
        {
            return false;
        }

        // The stamp decides on the NEW config's identity: the connection OBJECT plus its
        // version. A switch between connections, a repoint at a different secret reference,
        // a removal of the Connection metadata, or a rotation all change it — object
        // identity catches every reload that replaced the connection object, even when the
        // replacement's version restarts at 1 and collides with the old stamp's. A cluster
        // never seen by ConfigureHandler cannot be reused (its old client's identity is
        // unknown to this factory).
        var (connection, version) = ResolveStamp(context);
        return _certificateStamps.TryGetValue(context.ClusterId, out var stamp)
            && ReferenceEquals(stamp.Connection, connection)
            && stamp.Version == version;
    }

    /// <inheritdoc />
    protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(handler);

        base.ConfigureHandler(context, handler);

        var connection = ResolveConnection(context);
        if (connection is not null)
        {
            connection.Refresh();
            handler.SslOptions.ClientCertificates = new X509Certificate2Collection(connection.Certificate);
            _certificateStamps[context.ClusterId] = (connection, connection.Version);
        }
        else
        {
            // Record the no-cert identity too, so a later switch to (or from) a
            // resolvable connection rebuilds the client.
            var name = ResolveConnectionName(context);
            _certificateStamps[context.ClusterId] =
                (null, name is null ? NoConnectionVersion : UnknownConnectionVersion);
        }

        foreach (var feature in _services.GetServices<IConnectionFeature>())
        {
            feature.ConfigureHandler(handler);
        }
    }

    /// <inheritdoc />
    protected override HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(handler);

        return ComposePipeline(context, handler);
    }

    /// <summary>
    /// Composes the outbound handler chain for a cluster: the refresh-on-401 handler
    /// innermost (it acts on the real upstream response, below resilience), then the
    /// response dispatcher (M20, plan §8.2 — features run on the settled upstream
    /// response before YARP copies it), then the registered pipeline features in stage
    /// order, lowest stage outermost. Exposed for tests that compose over a stub
    /// transport.
    /// </summary>
    /// <param name="context">The cluster client context.</param>
    /// <param name="inner">The transport handler at the end of the chain.</param>
    /// <returns>The outermost handler of the chain.</returns>
    public HttpMessageHandler ComposePipeline(ForwarderHttpClientContext context, HttpMessageHandler inner)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(inner);

        var refreshOptions = _services.GetRequiredService<IOptions<RefreshOn401Options>>().Value;

        DelegatingHandler chain = new TokenRefreshHandler(ResolveTargets, refreshOptions)
        {
            InnerHandler = inner,
        };

        // The response dispatcher sits above the refresh handler: features run once per
        // caller-visible response — the 401 an internal refresh discards is never
        // dispatched — and the reshaped response is what YARP then copies to the caller
        // (M20, plan §8.2). A host without the pipeline registered (a bare factory
        // composition) has no response features to run and skips the dispatcher.
        if (_services.GetService<CredProxPipeline>() is { } pipeline)
        {
            chain = new ResponseDispatchHandler(
                chain,
                pipeline,
                _services.GetService<ILogger<ResponseDispatchHandler>>() ?? NullLogger<ResponseDispatchHandler>.Instance);
        }

        // Stage desc, then within a stage Order asc (lower = innermost), so composition
        // is deterministic regardless of registration order: resilience (Order 0) wraps
        // the refresh handler, throttling (Order 10) wraps resilience — one throttle
        // permit per caller request covers every resilience retry.
        var pipelineContext = new PipelineFeatureContext(context.ClusterId);
        foreach (var feature in _services.GetServices<IPipelineFeature>()
                     .OrderByDescending(f => f.Stage)
                     .ThenBy(f => f.Order))
        {
            chain = feature.CreateHandler(chain, pipelineContext);
        }

        return chain;
    }

    private static TokenRefreshTargets? ResolveTargets(HttpRequestMessage request) =>
        request.Options.TryGetValue(CredProxRequestOptions.TokenRefresh, out var targets) ? targets : null;

    /// <summary>
    /// The cluster's <see cref="CredProxMetadata.Connection"/> reference, resolved against
    /// the connection registry; <see langword="null"/> when the cluster names no connection
    /// or the named one is unknown. The identity comes from the <em>new</em> config's
    /// metadata only — falling back to the old metadata would keep a removed connection
    /// alive on the reuse path. The cluster metadata travels on the context itself (YARP
    /// passes the config's metadata), so no state lookup is needed.
    /// </summary>
    protected ClientCertificateConnection? ResolveConnection(ForwarderHttpClientContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var name = ResolveConnectionName(context);
        if (name is null)
        {
            return null;
        }

        // Resolved per call: in a configured host this is the live (reload-aware) registry,
        // so a connection added by a reload is usable without restarting the proxy.
        var connections = _services.GetService<ConnectionRegistry>();
        return connections is not null && connections.TryGet(name, out var connection)
            ? connection
            : null;
    }

    /// <summary>
    /// The current reuse stamp for a cluster: the connection <em>object</em> the new config
    /// resolves to, with its live version, or a null object with the sentinel version for
    /// no/unknown connection — each a distinct identity so switches, repoints and removals
    /// force a rebuild even when version numbers collide.
    /// </summary>
    private (ClientCertificateConnection? Connection, long Version) ResolveStamp(ForwarderHttpClientContext context)
    {
        var name = ResolveConnectionName(context);
        if (name is null)
        {
            return (null, NoConnectionVersion);
        }

        var connection = ResolveConnection(context);
        if (connection is null)
        {
            return (null, UnknownConnectionVersion);
        }

        connection.Refresh();
        return (connection, connection.Version);
    }

    private static string? ResolveConnectionName(ForwarderHttpClientContext context)
    {
        var metadata = context.NewMetadata;
        if (metadata is null
            || !metadata.TryGetValue(CredProxMetadata.Connection, out var name)
            || string.IsNullOrEmpty(name))
        {
            return null;
        }

        return name;
    }
}
