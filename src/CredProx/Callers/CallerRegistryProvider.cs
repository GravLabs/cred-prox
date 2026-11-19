using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="CallerRegistryGeneration"/> — the registry and every
/// contributor's committed data as one unit — and rebinds it when a change fires:
/// adding a caller, rotating a key (add the new key,
/// then remove the old one) or revoking a key all take effect without a restart. Both the
/// secret source's change token and (when it would add a signal) the configuration's
/// reload token trigger a rebind, so a configuration edit rebinds the registry even when
/// the host's secret source never signals — and one reload performs exactly one rebind
/// in the default callback order, whether it arrives through one trigger or the same
/// event through both. A host whose own reload callback registers on the shared
/// configuration before the source's callback can measure two binds for one reload —
/// both complete safely and no signal is dropped (see the constructor comment). A rebind that
/// fails — refused shape, or a contributor (key table)
/// that cannot build — keeps the previous generation and logs one error line naming the
/// reason: a bad reload must not turn a running proxy into one that authenticates nobody.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerRegistryProvider
{
    private readonly CallerBinder _binder;
    private readonly IReadOnlyList<ICallerRegistryContributor> _contributors;
    private readonly ILogger<CallerRegistryProvider> _logger;
    private readonly IConfiguration? _configuration;
    private readonly ISecretSource _secretSource;
    private readonly object _rebindGate = new();
    private volatile CallerRegistryGeneration _generation;

    // The single-flight record: the inputs of the last bind ATTEMPT — a hash over the
    // configuration values a rebind reads, and the secret-source token captured at the
    // attempt. A trigger whose inputs match this record is the same event arriving through
    // a second watch, not a new change.
    private string _attemptStamp;
    private IChangeToken? _secretToken;

    /// <summary>
    /// Creates the provider and performs the initial bind, with no contributors and the
    /// secret source's token as the only change trigger — the 0.11.0 shape. Hosts that
    /// feature packages contribute to (caller keys) use the full constructor so
    /// configuration reloads rebind and the packages' derived data commits with the
    /// registry.
    /// </summary>
    /// <param name="binder">The caller binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages name ids, never key material.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public CallerRegistryProvider(CallerBinder binder, ISecretSource secretSource, ILogger<CallerRegistryProvider> logger)
        : this(binder, [], null, secretSource, logger)
    {
    }

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The caller binder.</param>
    /// <param name="contributors">
    /// Derived-data contributors (see <see cref="ICallerRegistryContributor"/>). Each one
    /// runs inside every bind — initial and rebind — and its data commits with the
    /// registry as one <see cref="CallerRegistryGeneration"/>. A contributor that throws
    /// refuses the whole bind on the same path a refused shape takes.
    /// </param>
    /// <param name="configuration">
    /// The configuration root whose reload token also triggers a rebind; <see langword="null"/>
    /// keeps the 0.11.0 trigger set (the secret source's token only).
    /// </param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages name ids, never key material.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public CallerRegistryProvider(
        CallerBinder binder,
        IEnumerable<ICallerRegistryContributor> contributors,
        IConfiguration? configuration,
        ISecretSource secretSource,
        ILogger<CallerRegistryProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentNullException.ThrowIfNull(contributors);
        ArgumentNullException.ThrowIfNull(secretSource);
        ArgumentNullException.ThrowIfNull(logger);

        _binder = binder;
        _contributors = [.. contributors];
        _logger = logger;
        _configuration = configuration;
        _secretSource = secretSource;

        // Stamp the inputs the initial bind is about to read BEFORE binding: a reload that
        // lands between this read and the bind leaves the first trigger seeing a newer
        // stamp, and it rebinds — the safe direction for a miss is one extra bind.
        _attemptStamp = ComputeAttemptStamp();
        _secretToken = secretSource.GetChangeToken();
        _generation = Commit(_binder.Bind());

        // ChangeToken.OnChange re-arms, so these keep firing across reloads; the
        // registrations live as long as this singleton. One observed change performs
        // exactly one bind ATTEMPT. A source that is configuration over this very root is
        // watched through its own token only (see SourceAlreadyWatchesConfiguration): its
        // token fires on every reload of that root, so a second watch would only deliver
        // the same reload again. A host whose source is not configuration-backed keeps
        // both watches, and a trigger whose inputs match the last bind attempt's is the
        // same event arriving through the second watch — dropped with one debug line.
        // A refused change therefore writes ONE error line per attempt and an accepted one
        // resolves each contributed secret exactly once, whatever the host's source
        // topology; a genuine change — configuration values the binder reads, or a fresh
        // secret-source signal — always rebinds.
        // Callback order, two-watch hosts: the source watch below is registered before the
        // root watch, but when a host's two watches observe one reload through two different
        // IConfiguration instances over the same providers, the order the callbacks run is
        // set by which root registered its reload callback on those providers first — the
        // host's own build order, not this class. The two-watch accepted-reload cell builds
        // the shape where the source's root is that first registration: the source callback
        // binds with the fresh token, the root callback that follows sees an unchanged token
        // over an unchanged stamp and drops, and the cell pins binds == 1 with one drop line,
        // so a host-shape flip fails a test rather than only this comment. Were the root
        // callback ever first, it would capture a source token the same reload then cancels,
        // and the source trigger following it would legitimately re-attempt through
        // HasChanged — the second attempt the note on SourceAlreadyWatchesConfiguration
        // documents: two binds for one reload.
        ChangeToken.OnChange(secretSource.GetChangeToken, RebindIfChanged);
        if (configuration is not null && !SourceAlreadyWatchesConfiguration(secretSource, configuration))
        {
            ChangeToken.OnChange(configuration.GetReloadToken, RebindIfChanged);
        }
    }

    // True when the source's change signal already covers this configuration root, so a
    // separate watch on the root would duplicate every reload. Only the core's own
    // configuration-backed source can carry the marker; a third-party source keeps the
    // two-watch shape, where the attempt stamp coalesces the same event arriving twice —
    // and one that re-fires its own token mid-reload can honestly present a new signal to
    // the second watch, making a second attempt. That is documented behavior, not a defect
    // to paper over: dropping it could swallow a real signal.
    private static bool SourceAlreadyWatchesConfiguration(ISecretSource secretSource, IConfiguration configuration) =>
        secretSource is IConfigurationBackedSecretSource bound && ReferenceEquals(bound.Configuration, configuration);

    private void RebindIfChanged()
    {
        lock (_rebindGate)
        {
            var secretToken = _secretToken;
            var secretChanged = secretToken is null || secretToken.HasChanged;
            var stamp = ComputeAttemptStamp();
            if (!secretChanged && stamp == _attemptStamp)
            {
                // This exact state was already attempted — the same event arriving through
                // a second watch, or a reload that touched nothing the registry reads. A
                // second bind would double the outcome: two error lines on a refused
                // change, two resolution passes on an accepted one. Say so at debug: a
                // dropped trigger must not read as silence after a reload. No stamp
                // value — or any configuration value — ever enters a log line.
                _logger.LogDebug(
                    "CredProx callers rebind trigger dropped: configuration unchanged since the last bind attempt and no new secret-source signal.");
                return;
            }

            _attemptStamp = stamp;

            // Capture BEFORE the bind, never after: a secret-source signal that lands
            // while this bind runs cancels the token captured here, so the next trigger
            // sees HasChanged and re-attempts. Capturing after the bind would swallow a
            // mid-bind signal until some unrelated trigger woke the provider.
            _secretToken = _secretSource.GetChangeToken();
            Rebind();
        }
    }

    // A change-detector stamp over what a rebind reads from configuration: the raw values
    // under CredProx:Callers that the binder and every contributor consume. Sections are
    // read case-insensitively and an environment source delivers its keys upper-cased, so
    // the section filter ignores case too: matching one spelling only would freeze the
    // stamp while the values every consumer reads move, and the rotation would never
    // rebind. The hash keeps
    // raw config (which can hold key material) out of the retained record, and the stamp
    // itself is never logged. Secret VALUES are deliberately absent: a rotated secret is
    // invisible to configuration but fires the source's change token, tracked separately.
    private string ComputeAttemptStamp()
    {
        if (_configuration is null)
        {
            return "no-configuration";
        }

        using var sha = SHA256.Create();
        foreach (var pair in _configuration.AsEnumerable(true)
                     .Where(pair => pair.Key.StartsWith("CredProx:Callers", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            var bytes = Encoding.UTF8.GetBytes(string.Concat(pair.Key, "=", pair.Value, "\n"));
            sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        }

        sha.TransformFinalBlock([], 0, 0);
        return Convert.ToHexString(sha.Hash!);
    }

    /// <summary>The registry to serve requests from; swapped atomically on rebind.</summary>
    public CallerRegistry Current => _generation.Registry;

    /// <summary>
    /// The live generation — the registry plus every contributor's data, committed together.
    /// Take this (not <see cref="Current"/>) when reading derived data: the pair is one
    /// atomic snapshot.
    /// </summary>
    public CallerRegistryGeneration CurrentGeneration => _generation;

    private CallerRegistryGeneration Commit(CallerRegistry registry)
    {
        var contributed = new Dictionary<Type, object>(_contributors.Count);
        foreach (var contributor in _contributors)
        {
            // Runs inside the bind: a throw here refuses this bind exactly like a refused
            // shape — the initial bind fails startup, a rebind keeps the previous
            // generation serving. Nothing is committed until every contributor returned.
            contributed[contributor.GetType()] = contributor.Contribute(registry);
        }

        return new CallerRegistryGeneration(registry, contributed);
    }

    private void Rebind()
    {
        try
        {
            _generation = Commit(_binder.Rebind(_generation.Registry));
            _logger.LogInformation("CredProx callers rebound after a configuration change.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "CredProx callers failed to rebind after a configuration change; keeping the previous registry.");
        }
    }
}
