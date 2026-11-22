using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Reflection;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds every <c>CredProx:Credentials:&lt;name&gt;</c> section at startup: the section's
/// <c>Type</c> must name a registered credential type (unknown types fail startup, never
/// fall back to a default), the options are bound and validated, and the secret accessor is
/// scoped to the section. A section may reference a preset by name; the preset layers
/// beneath the host's fields and an unknown preset is a startup error. All
/// problems are collected into one
/// <see cref="OptionsValidationException"/> naming the credentials — never values.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CredentialBinder
{
    private readonly IConfiguration _configuration;
    private readonly SecretAccessorFactory _accessorFactory;
    private readonly IServiceProvider _services;
    private readonly IReadOnlyList<CredentialTypeRegistration> _registrations;
    private readonly IReadOnlyList<IPartitionSourceFactory> _partitionFactories;
    private readonly IReadOnlyList<IPresetSource> _presetSources;

    /// <summary>Creates the binder.</summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="accessorFactory">Creates the per-credential scoped secret accessors.</param>
    /// <param name="services">Resolves provider instances and options validators.</param>
    /// <param name="registrations">The explicitly registered credential types.</param>
    /// <param name="partitionFactories">The registered partition source factories.</param>
    /// <param name="presetSources">The preset sources consulted for <c>Preset</c> references.</param>
    public CredentialBinder(
        IConfiguration configuration,
        SecretAccessorFactory accessorFactory,
        IServiceProvider services,
        IEnumerable<CredentialTypeRegistration> registrations,
        IEnumerable<IPartitionSourceFactory> partitionFactories,
        IEnumerable<IPresetSource> presetSources)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _accessorFactory = accessorFactory ?? throw new ArgumentNullException(nameof(accessorFactory));
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _registrations = (registrations ?? throw new ArgumentNullException(nameof(registrations))).ToList();
        _partitionFactories = (partitionFactories ?? throw new ArgumentNullException(nameof(partitionFactories))).ToList();
        _presetSources = (presetSources ?? throw new ArgumentNullException(nameof(presetSources))).ToList();
    }

    /// <summary>
    /// Binds every configured credential into a <see cref="CredentialRegistry"/>.
    /// </summary>
    /// <exception cref="OptionsValidationException">
    /// A credential has no <c>Type</c>, an unknown <c>Type</c>, an unknown <c>Preset</c>,
    /// or failing options validation.
    /// </exception>
    public CredentialRegistry Bind()
    {
        var errors = new List<string>();
        var bindings = new Dictionary<string, CredentialBinding>(StringComparer.OrdinalIgnoreCase);

        // A credential section may reference a preset; the fragment layers beneath the
        // host's own keys, so every field the host writes still wins (§3 "Vendor presets").
        var effective = PresetConfiguration.Compose(_configuration, _presetSources, errors);

        foreach (var section in effective.GetSection("CredProx:Credentials").GetChildren())
        {
            var name = section.Key;
            var typeName = section["Type"];
            if (string.IsNullOrEmpty(typeName))
            {
                errors.Add($"The credential '{name}' has no Type.");
                continue;
            }

            var registration = _registrations.FirstOrDefault(
                r => string.Equals(r.TypeName, typeName, StringComparison.Ordinal));
            if (registration is null)
            {
                var known = string.Join(", ", _registrations.Select(r => r.TypeName).Order(StringComparer.Ordinal));
                // R2 (ADR-0007): a type the core does not ship names its package and its
                // one call — the only package knowledge the core keeps, as strings, so a
                // host that skipped the add-on setup hears the fix at startup. One shape:
                // "<thing> needs the <package> package: install it and call <call>."
                // Hmac and LoginExchange ride the core since M49 and never reach here.
                var packageHint = typeName switch
                {
                    "OAuthClientCredentials" or "TokenExchange" or "JwtAssertion" =>
                        $" Credential type '{typeName}' needs the CredProx.Identity package: install it and call .AddIdentity().",
                    "TokenCredential" =>
                        " Credential type 'TokenCredential' needs the CredProx.Azure package: install it and call .AddAzure(credential).",
                    _ => string.Empty,
                };
                errors.Add(
                    $"The credential '{name}' uses unknown credential Type '{typeName}'. Registered types: {known}.{packageHint}");
                continue;
            }

            // M16 (§3.3): keys the binder does not consume are silently ignored by section.Bind,
            // so a misspelled optional field (e.g. "Scopee" for "Scope") binds to nothing and the
            // credential runs without the setting it was meant to have — the same fail-open M14a
            // closed for callers. The allowed keys come from the options type by reflection, so a
            // plugin credential declares its own keys simply by having them on its options type.
            // This runs on the effective (post-preset) section, so host keys, preset-supplied keys
            // and reloads are all covered; a rejected rebind keeps the previous registry.
            var before = errors.Count;
            ConfigKeyValidator.RejectUnknownKeys(
                section, registration.OptionsType, $"credential '{name}'",
                $"CredProx:Credentials:{name}", errors, addTypeAndPreset: true);
            if (errors.Count > before)
            {
                continue;
            }

            var options = Activator.CreateInstance(registration.OptionsType)!;
            section.Bind(options);

            var validationErrors = ValidateOptions(name, registration.OptionsType, options);
            if (validationErrors.Count > 0)
            {
                errors.AddRange(validationErrors.Select(e => $"The credential '{name}': {e}"));
                continue;
            }

            var secrets = _accessorFactory.CreateAccessor(section);
            object provider;
            try
            {
                provider = _services.GetRequiredService(registration.ProviderType);
            }
            catch (InvalidOperationException ex)
            {
                // The type is registered but its own dependencies are not — a startup
                // misconfiguration, reported like every other binding problem.
                errors.Add(
                    $"The credential '{name}' of Type '{typeName}' cannot be constructed: {ex.Message}");
                continue;
            }

            PartitionSourceBinding? partitionSource = null;
            if (options is IHasPartitionConfig { Partition: { } partitionConfig })
            {
                if (!PartitionBinder.TryBind(
                        partitionConfig.From, partitionConfig.Allowed, _partitionFactories,
                        $"credential '{name}'", out partitionSource, out var partitionError))
                {
                    errors.Add(partitionError!);
                    continue;
                }
            }

            bindings[name] = new CredentialBinding
            {
                Name = name,
                TypeName = registration.TypeName,
                Options = options,
                PartitionSource = partitionSource,
                ConnectionName = (options as IHasConnection)?.Connection,
                GetCredential = (Func<CredentialRequestContext, CancellationToken, ValueTask<string>>)
                    BuildGetterMethod.MakeGenericMethod(registration.ProviderType, registration.OptionsType)
                        .Invoke(null, [provider, options, secrets])!,
                Attach = options is IHasAttachment attachment
                    ? (request, value) => CredentialAttacher.Apply(request, attachment.Location, attachment.Name, value, attachment.Prefix)
                    : null,
            };
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return new CredentialRegistry(bindings);
    }

    // The credential's configured name is handed to validators as the options name:
    // a validator that advises (rather than rejects) must be able to say WHICH
    // credential it advises about, and the binder is the only place that knows it.
    private List<string> ValidateOptions(string? credentialName, Type optionsType, object options)
    {
        var errors = new List<string>();
        var validatorType = typeof(IValidateOptions<>).MakeGenericType(optionsType);
        var validate = validatorType.GetMethod(nameof(IValidateOptions<object>.Validate))!;

        foreach (var validator in _services.GetServices(validatorType))
        {
            if (validate.Invoke(validator, [credentialName, options]) is ValidateOptionsResult { Failed: true } result)
            {
                errors.AddRange(result.Failures!);
            }
        }

        return errors;
    }

    private static readonly MethodInfo BuildGetterMethod =
        typeof(CredentialBinder).GetMethod(nameof(BuildGetter), BindingFlags.NonPublic | BindingFlags.Static)!;

    private static Func<CredentialRequestContext, CancellationToken, ValueTask<string>> BuildGetter<TProvider, TOptions>(
        object provider,
        object options,
        ISecretAccessor secrets)
        where TProvider : ICredentialProvider<TOptions>
        where TOptions : class
    {
        var typed = (TProvider)provider;
        var typedOptions = (TOptions)options;
        return (context, cancellationToken) => typed.GetCredentialAsync(typedOptions, secrets, context, cancellationToken);
    }
}
