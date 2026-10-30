using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.Sign"/> feature for <c>Hmac</c> credentials
/// (see <c>docs/credprox-plan.md</c> §4 Phase C "HMAC signing"): builds the configured
/// canonical string from the FINAL outbound request form — the stage runs after header
/// shaping and credential attachment, so a signature over an earlier form can never be
/// produced — computes the HMAC over the resolved key, and writes the signature (and
/// optional timestamp) headers. The body is buffered only when the recipe needs
/// <c>bodyHash</c> and <see cref="HmacOptions.BufferBody"/> is on; a body over
/// <see cref="HmacOptions.MaxBodyBytes"/> answers
/// <c>413 credprox.body_too_large_to_sign</c> and is not forwarded (§3.4 line 205).
/// Routes whose credential is not an <c>Hmac</c> — and routes with no credential — pass
/// through untouched.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class HmacSignFeature : IRequestFeature
{
    private readonly CredentialRegistryProvider _registryProvider;
    private readonly TimeProvider _time;
    private readonly ILogger<HmacSignFeature> _logger;

    /// <summary>Creates the feature.</summary>
    /// <param name="registryProvider">The reload-aware credential registry.</param>
    /// <param name="time">The time source for the timestamp component (§5.2).</param>
    /// <param name="logger">Logs signing failures (messages never contain keys).</param>
    public HmacSignFeature(
        CredentialRegistryProvider registryProvider,
        TimeProvider time,
        ILogger<HmacSignFeature> logger)
    {
        _registryProvider = registryProvider ?? throw new ArgumentNullException(nameof(registryProvider));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Stage Stage => Stage.Sign;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state || state.IsAborted)
        {
            return;
        }

        if (CredProxMetadata.GetRouteMetadata(context) is not { } metadata
            || !metadata.TryGetValue(CredProxMetadata.Credential, out var name)
            || string.IsNullOrEmpty(name))
        {
            return; // route attaches no credential
        }

        var binding = _registryProvider.Current.Get(name);
        if (binding.TypeName != "Hmac")
        {
            return; // only HMAC credentials sign at this stage
        }

        var options = (HmacOptions)binding.Options;

        var components = new List<(HmacComponentKind, string)>(options.Components.Count);
        var needsBody = false;
        foreach (var token in options.Components)
        {
            if (!HmacSigner.TryParseComponent(token, out var kind, out var argument))
            {
                // Unreachable for validated configs; fail closed rather than sign a
                // canonical string the verifier cannot reproduce.
                await AbortSigningErrorAsync(state, name,
                    $"The HMAC credential '{name}' has an unparseable canonical-string component '{token}'.")
                    .ConfigureAwait(false);
                return;
            }

            components.Add((kind, argument));
            needsBody |= kind == HmacComponentKind.BodyHash;
        }

        byte[] body = [];
        if (needsBody && state.ProxyRequest.Content is { } content)
        {
            if (content.Headers.ContentLength > options.MaxBodyBytes)
            {
                await state.AbortAsync(
                    StatusCodes.Status413PayloadTooLarge,
                    "credprox.body_too_large_to_sign",
                    "The request body is too large to sign.").ConfigureAwait(false);
                return;
            }

            if (!options.BufferBody)
            {
                // Validator rejects this combination; defensive fail-closed.
                await AbortSigningErrorAsync(state, name,
                    $"The HMAC credential '{name}' needs body buffering for the bodyHash component; enable BufferBody.")
                    .ConfigureAwait(false);
                return;
            }

            try
            {
                await content.LoadIntoBufferAsync(options.MaxBodyBytes).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                // LoadIntoBufferAsync throws when the cap is exceeded mid-read (unknown
                // length larger than the cap).
                await state.AbortAsync(
                    StatusCodes.Status413PayloadTooLarge,
                    "credprox.body_too_large_to_sign",
                    "The request body is too large to sign.").ConfigureAwait(false);
                return;
            }

            body = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        }

        string key;
        try
        {
            var credentialContext = new CredentialRequestContext { CredentialName = name, Partition = state.Partition };
            key = await binding.GetCredential(credentialContext, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            await AbortSigningErrorAsync(state, name,
                $"The HMAC credential '{name}' could not be obtained for this request: {ex.Message}")
                .ConfigureAwait(false);
            return;
        }

        var now = _time.GetUtcNow();
        var canonical = HmacSigner.BuildCanonicalString(
            components, state.ProxyRequest, body, options, now, state.OutboundPath, state.OutboundQuery);
        var signature = HmacSigner.Sign(canonical, key, options);

        // Replace, never merge: a caller-supplied signature header is not carried through
        // (§3.4 header hygiene, same rule as credential attachment).
        state.ProxyRequest.Headers.Remove(options.SignatureHeader!);
        state.ProxyRequest.Headers.Add(
            options.SignatureHeader!,
            string.IsNullOrEmpty(options.SchemePrefix) ? signature : options.SchemePrefix + signature);

        if (options.TimestampHeader is { } timestampHeader)
        {
            var timestamp = HmacSigner.FormatTimestamp(now, options.TimestampFormat);
            state.ProxyRequest.Headers.Remove(timestampHeader);
            state.ProxyRequest.Headers.Add(timestampHeader, timestamp);
        }
    }

    private async ValueTask AbortSigningErrorAsync(CredProxRequestState state, string name, string logMessage)
    {
        _logger.LogWarning("{Message}", logMessage);
        await state
            .AbortAsync(StatusCodes.Status502BadGateway, "credprox.credential_unavailable",
                "The outbound credential could not be obtained.")
            .ConfigureAwait(false);
    }
}
