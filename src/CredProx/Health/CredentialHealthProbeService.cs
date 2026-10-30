using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The background probe loop (§4 "Credential health"): runs every registered
/// <see cref="ICredentialHealthProbe"/> on the configured interval — first round at
/// startup — swaps the result into the <see cref="CredentialHealthSnapshot"/> and logs
/// on state transitions only: into Degraded (warning), into Unhealthy (error), and
/// recovery (information). A probe that throws is an Unhealthy round for that probe,
/// never a crash of the loop.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CredentialHealthProbeService : BackgroundService
{
    private readonly IReadOnlyList<ICredentialHealthProbe> _probes;
    private readonly CredentialHealthSnapshot _snapshot;
    private readonly CredProxHealthOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Dictionary<string, int> _lastSeverity = new(StringComparer.Ordinal);

    public CredentialHealthProbeService(
        IEnumerable<ICredentialHealthProbe> probes,
        CredentialHealthSnapshot snapshot,
        CredProxHealthOptions options,
        TimeProvider time,
        ILogger<CredentialHealthProbeService> logger)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);

        _probes = [.. probes];
        _snapshot = snapshot;
        _options = options;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            return;
        }

        using var timer = new PeriodicTimer(_options.ProbeInterval, _time);
        try
        {
            do
            {
                await RunRoundAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Shutdown mid-round or mid-wait: the loop simply ends.
        }
    }

    private async Task RunRoundAsync(CancellationToken cancellationToken)
    {
        var results = new List<HealthProbeResult>(_probes.Count);

        foreach (var probe in _probes)
        {
            CredProxHealthResult? failure;
            try
            {
                failure = await probe.CheckAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // A broken probe is an Unhealthy result, not a dead loop. Messages are
                // value-free by the provider discipline they break out of.
                failure = new CredProxHealthResult(
                    CredProxHealthSeverity.Unhealthy, $"the probe threw: {ex.Message}");
            }

            var severity = failure is null
                ? 0
                : failure.Severity == CredProxHealthSeverity.Degraded ? 1 : 2;

            results.Add(new HealthProbeResult(probe.Name, severity, failure?.Description, _time.GetUtcNow()));
            CredProxDiagnostics.RecordHealthStatus("probe", probe.Name, severity);
            LogTransition(probe.Name, severity, failure?.Description);
        }

        _snapshot.Update(results);
    }

    private void LogTransition(string name, int severity, string? description)
    {
        var previous = _lastSeverity.TryGetValue(name, out var seen) ? seen : 0;
        _lastSeverity[name] = severity;
        if (severity == previous)
        {
            return;
        }

        switch (severity)
        {
            case 0:
                _logger.LogInformation("The CredProx health probe '{Probe}' recovered.", name);
                break;
            case 1:
                _logger.LogWarning(
                    "The CredProx health probe '{Probe}' is Degraded: {Description}", name, description);
                break;
            default:
                _logger.LogError(
                    "The CredProx health probe '{Probe}' is Unhealthy: {Description}", name, description);
                break;
        }
    }
}
