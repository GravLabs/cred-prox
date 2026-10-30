using System.Diagnostics.CodeAnalysis;
using System.Text;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;

namespace CredProx;

/// <summary>
/// The CredProx startup gate (§3.3 "Validation"), run as the host starts:
/// <list type="bullet">
/// <item>resolves the credential, destination and connection registries — every section
/// binds and every client certificate loads before traffic (no lazy first-request
/// surprises);</item>
/// <item>resolves every literal <c>secret:</c> reference — including ones a referenced
/// preset introduces — and rejects nested-brace secret declarations (§3.2 shapes only);</item>
/// <item>warns on fully-dynamic secret declarations whose shape admits every name;</item>
/// <item>checks every YARP <c>CredProx.Credential</c> / <c>CredProx.Destination</c> /
/// <c>CredProx.Connection</c> metadata reference and every credential's
/// <c>Connection</c> option against the registries;</item>
/// <item>when caller authentication is registered, binds <c>CredProx:Callers</c> and
/// checks every caller operation <c>Route</c> reference against the configured routes;</item>
/// <item>binds <c>CredProx:KillSwitch</c> (M18, §8.4), so a switch that cannot be read is
/// a startup failure and never an unarmed switch.</item>
/// </list>
/// All problems are collected into one <see cref="OptionsValidationException"/> naming
/// references — never values (§5.2 "Validation").
/// </summary>
/// <remarks>
/// This is the startup gate; after startup, <see cref="CredProxConfigValidator"/> re-runs
/// the metadata cross-checks on every YARP configuration load, so a bad reload is refused
/// and the previous configuration keeps serving (M5 note N1).
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxStartupValidator : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly IReadOnlyList<IProxyConfigProvider> _proxyConfigProviders;
    private readonly IConfiguration _configuration;
    private readonly SecretReferenceValidator _secretValidator;
    private readonly IReadOnlyList<IPresetSource> _presetSources;
    private readonly ILogger<CredProxStartupValidator> _logger;

    /// <summary>Creates the validator.</summary>
    /// <param name="services">Resolves the registries eagerly.</param>
    /// <param name="proxyConfigProviders">The YARP config sources whose metadata is checked.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="secretValidator">The literal-reference resolver from M2.</param>
    /// <param name="presetSources">The preset sources, so preset-introduced secret references are scanned too.</param>
    /// <param name="logger">Logs fully-dynamic declaration warnings.</param>
    public CredProxStartupValidator(
        IServiceProvider services,
        IEnumerable<IProxyConfigProvider> proxyConfigProviders,
        IConfiguration configuration,
        SecretReferenceValidator secretValidator,
        IEnumerable<IPresetSource> presetSources,
        ILogger<CredProxStartupValidator> logger)
    {
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _proxyConfigProviders = (proxyConfigProviders ?? throw new ArgumentNullException(nameof(proxyConfigProviders))).ToList();
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _secretValidator = secretValidator ?? throw new ArgumentNullException(nameof(secretValidator));
        _presetSources = (presetSources ?? throw new ArgumentNullException(nameof(presetSources))).ToList();
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var errors = new List<string>();

        // Eager binds: the constructors throw OptionsValidationException with their own
        // collected errors; resolve them all so one startup reports everything fixable.
        CredentialRegistry? credentials = null;
        DestinationRegistry? destinations = null;
        ConnectionRegistry? connections = null;

        try
        {
            credentials = _services.GetRequiredService<CredentialRegistry>();
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        try
        {
            destinations = _services.GetService<DestinationRegistry>();
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        try
        {
            connections = _services.GetService<ConnectionRegistry>();
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        CallerRegistry? callers = null;
        try
        {
            // Optional: present only when caller authentication is registered. The
            // provider's constructor performs the initial bind, so resolving it here is
            // what makes a bad caller section a startup failure rather than a
            // first-request surprise.
            callers = _services.GetService<CallerRegistry>();
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        try
        {
            // The kill switch (M18, §8.4): bound eagerly too — a section that refuses
            // validation must fail startup, not first leave the switch unarmed until the
            // first request the operator meant to block.
            _ = _services.GetService<KillSwitchRegistry>();
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        // Scan the preset-composed view: a secret reference a preset introduces must
        // resolve through the host's secret source just like one the host wrote (§5.2
        // "Presets"). Unknown-preset errors are reported by the binder, not duplicated here.
        var credProxSection = PresetConfiguration
            .Compose(_configuration, _presetSources, [])
            .GetSection("CredProx");

        try
        {
            await _secretValidator.ValidateAsync(credProxSection, cancellationToken).ConfigureAwait(false);
        }
        catch (OptionsValidationException ex)
        {
            errors.AddRange(ex.Failures);
        }

        ScanSecretDeclarations(credProxSection, errors);

        ValidateProxyMetadata(errors, credentials, destinations, connections, callers);

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Rejects nested-brace secret declarations (<c>{secret:a{secret:b}c}</c> — a shape
    /// nothing resolves and scoping cannot bound) and warns on fully-dynamic ones
    /// (<c>secret:{partition}</c> — a shape that admits every name).
    /// </summary>
    private void ScanSecretDeclarations(IConfigurationSection credProxSection, List<string> errors)
    {
        foreach (var (path, value) in credProxSection.AsEnumerable())
        {
            if (value is null)
            {
                continue;
            }

            foreach (var name in SecretReferences.FindInValue(value))
            {
                if (name.Contains("{secret:", StringComparison.Ordinal))
                {
                    errors.Add(
                        $"The value at '{path}' declares a nested secret reference; secret references must not contain other references.");
                }
                else if (IsFullyDynamic(name))
                {
                    _logger.LogWarning(
                        "The value at '{Path}' declares the fully-dynamic secret shape '{Shape}', which admits every secret name; narrow the declaration.",
                        path, name);
                }
            }
        }
    }

    /// <summary>
    /// A declared name is fully dynamic when, with every <c>{placeholder}</c> segment
    /// removed, nothing literal remains — the shape then matches any name.
    /// </summary>
    private static bool IsFullyDynamic(string name)
    {
        if (!name.Contains('{', StringComparison.Ordinal))
        {
            return false;
        }

        var literal = new StringBuilder(name.Length);
        var inPlaceholder = false;
        foreach (var c in name)
        {
            if (c == '{')
            {
                inPlaceholder = true;
            }
            else if (c == '}')
            {
                inPlaceholder = false;
            }
            else if (!inPlaceholder)
            {
                literal.Append(c);
            }
        }

        return literal.Length == 0;
    }

    private void ValidateProxyMetadata(
        List<string> errors,
        CredentialRegistry? credentials,
        DestinationRegistry? destinations,
        ConnectionRegistry? connections,
        CallerRegistry? callers)
    {
        // Route ids across all providers, for caller operation Route references below.
        var routeIds = callers is null
            ? null
            : new HashSet<string>(
                _proxyConfigProviders.SelectMany(p => p.GetConfig().Routes).Select(r => r.RouteId),
                StringComparer.Ordinal);

        foreach (var provider in _proxyConfigProviders)
        {
            var proxyConfig = provider.GetConfig();

            foreach (var route in proxyConfig.Routes)
            {
                var metadata = route.Metadata;
                if (metadata is null)
                {
                    continue;
                }

                if (metadata.TryGetValue(CredProxMetadata.Credential, out var credentialName)
                    && !string.IsNullOrEmpty(credentialName))
                {
                    if (credentials is null || !credentials.TryGet(credentialName, out var binding))
                    {
                        errors.Add(
                            $"Route '{route.RouteId}' references unknown credential '{credentialName}' in {CredProxMetadata.Credential}.");
                    }
                    else if (binding.ConnectionName is { } connectionName
                        && (connections is null || !connections.TryGet(connectionName, out _)))
                    {
                        errors.Add(
                            $"The credential '{credentialName}' references unknown connection '{connectionName}' in its Connection option.");
                    }
                }

                if (metadata.TryGetValue(CredProxMetadata.Destination, out var destinationName)
                    && !string.IsNullOrEmpty(destinationName)
                    && (destinations is null || !destinations.TryGet(destinationName, out _)))
                {
                    errors.Add(
                        $"Route '{route.RouteId}' references unknown destination '{destinationName}' in {CredProxMetadata.Destination}.");
                }
            }

            foreach (var cluster in proxyConfig.Clusters)
            {
                if (cluster.Metadata is { } metadata
                    && metadata.TryGetValue(CredProxMetadata.Connection, out var connectionName)
                    && !string.IsNullOrEmpty(connectionName)
                    && (connections is null || !connections.TryGet(connectionName, out _)))
                {
                    errors.Add(
                        $"Cluster '{cluster.ClusterId}' references unknown connection '{connectionName}' in {CredProxMetadata.Connection}.");
                }
            }
        }

        // Caller operation entries may pin a route; a reference to a route that does not
        // exist would silently never match, so it fails startup (startup only — a reload
        // that removes a route leaves the caller registry serving, and the entry then
        // simply matches nothing, which is fail-closed).
        if (callers is not null && routeIds is not null)
        {
            foreach (var callerId in callers.CallerIds)
            {
                foreach (var rule in callers.Get(callerId).Operations)
                {
                    if (rule.Route is { } routeRef && !routeIds.Contains(routeRef))
                    {
                        errors.Add($"The caller '{callerId}' declares an operation for unknown route '{routeRef}'.");
                    }
                }
            }
        }
    }
}
