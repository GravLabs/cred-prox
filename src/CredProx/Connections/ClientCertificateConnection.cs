using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// One <c>CredProx:Connections:&lt;name&gt;</c> entry (see <c>docs/credprox-plan.md</c>
/// §3.2): a client certificate loaded from a secret, with rotation detection. The raw
/// secret value is compared on each refresh; when it changed, the certificate is reloaded
/// and <see cref="Version"/> advances. <c>CredProxForwarderHttpClientFactory</c> adds that
/// version to its <c>CanReuseOldClient</c> check, so a rotated certificate rebuilds the
/// cluster's client on the next configuration reload (§3.3).
/// </summary>
/// <remarks>
/// A reload that fails to load (a rotated value that is not valid certificate material, or
/// a secret that momentarily does not resolve) keeps serving the previous certificate and
/// logs the failure — an outage of the secret store must not take down live mTLS
/// connections. The replaced certificate is not disposed: an in-flight client may still
/// reference it; it is released when that client is.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ClientCertificateConnection
{
    private readonly ISecretAccessor _secrets;
    private readonly ILogger _logger;
    private readonly object _gate = new();

    private X509Certificate2? _certificate;
    private string? _rawValue;
    private string? _rawPassword;

    internal ClientCertificateConnection(
        string name,
        ISecretAccessor secrets,
        string certificateReference,
        string? passwordReference,
        ILogger logger)
    {
        Name = name;
        _secrets = secrets;
        CertificateReference = certificateReference;
        PasswordReference = passwordReference;
        _logger = logger;
    }

    /// <summary>The connection name from configuration.</summary>
    public string Name { get; }

    /// <summary>The certificate's secret reference (a name, never a value).</summary>
    public string CertificateReference { get; }

    /// <summary>The password's secret reference, or <see langword="null"/> when unconfigured.</summary>
    public string? PasswordReference { get; }

    /// <summary>
    /// Advances whenever the certificate material is reloaded after a change. Captured by
    /// the client factory when a client is built and compared on reuse checks.
    /// </summary>
    public long Version { get; private set; }

    /// <summary>The current certificate. Requires a successful load (startup guarantees one).</summary>
    /// <exception cref="InvalidOperationException">No certificate has loaded yet.</exception>
    public X509Certificate2 Certificate
    {
        get
        {
            lock (_gate)
            {
                return _certificate ?? throw new InvalidOperationException(
                    $"The connection '{Name}' has no loaded client certificate.");
            }
        }
    }

    /// <summary>
    /// Loads the certificate for the first time, letting failures surface — the startup
    /// binder turns them into the validation error §5.2 requires.
    /// </summary>
    /// <param name="cancellationToken">Cancels the secret reads.</param>
    public ValueTask LoadAsync(CancellationToken cancellationToken) =>
        RefreshCoreAsync(throwOnFailure: true, cancellationToken);

    /// <summary>
    /// Re-reads the secret and reloads the certificate when the value changed.
    /// Failures keep the previous certificate (see remarks).
    /// </summary>
    /// <param name="cancellationToken">Cancels the secret reads.</param>
    public ValueTask RefreshAsync(CancellationToken cancellationToken) =>
        RefreshCoreAsync(throwOnFailure: false, cancellationToken);

    private async ValueTask RefreshCoreAsync(bool throwOnFailure, CancellationToken cancellationToken)
    {
        string raw;
        string? password;
        try
        {
            raw = await SecretValues
                .ResolveIfReferenceAsync(CertificateReference, _secrets, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    $"The client certificate reference '{CertificateReference}' does not resolve.");
            password = PasswordReference is null
                ? null
                : await SecretValues
                    .ResolveIfReferenceAsync(PasswordReference, _secrets, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (throwOnFailure)
            {
                throw;
            }

            _logger.LogError(
                "The connection '{Connection}' could not re-read its client certificate secret; keeping the current certificate. {Error}",
                Name, ex.Message);
            return;
        }

        lock (_gate)
        {
            if (_certificate is not null && raw == _rawValue && password == _rawPassword)
            {
                return;
            }
        }

        X509Certificate2 certificate;
        try
        {
            certificate = ClientCertificateLoader.Load(raw, password, CertificateReference);
        }
        catch (Exception ex)
        {
            if (throwOnFailure)
            {
                throw;
            }

            _logger.LogError(
                "The connection '{Connection}' could not reload its client certificate; keeping the current certificate. {Error}",
                Name, ex.Message);
            return;
        }

        lock (_gate)
        {
            _certificate = certificate;
            _rawValue = raw;
            _rawPassword = password;
            Version++;
        }
    }

    /// <summary>
    /// Synchronous refresh for the client factory's reuse check, which YARP calls from
    /// synchronous code. Configuration-backed sources complete inline; a remote secret
    /// source briefly blocks this thread during a configuration reload.
    /// </summary>
    public void Refresh() => RefreshAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
}
