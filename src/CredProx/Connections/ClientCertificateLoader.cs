using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CredProx;

/// <summary>
/// Loads a client certificate from a secret value (see <c>docs/credprox-plan.md</c> §3.2:
/// <c>"ClientCertificate": "secret:adp-auth-cert"</c>). Two shapes are accepted: a PEM
/// bundle containing at least one certificate and one private key (encrypted keys need the
/// configured password), and a base64-encoded PKCS#12 (PFX) blob. Failure messages name
/// the reference and the failure kind — never the value, the password, or key material.
/// </summary>
internal static class ClientCertificateLoader
{
    /// <summary>
    /// Loads the certificate, requiring a usable private key.
    /// </summary>
    /// <param name="rawValue">The secret value: PEM bundle or base64 PFX.</param>
    /// <param name="password">The PFX / encrypted-PEM password, or <see langword="null"/>.</param>
    /// <param name="displayName">The reference name for error text; never a secret.</param>
    /// <exception cref="InvalidOperationException">
    /// The value is not loadable certificate material or the password is wrong.
    /// </exception>
    public static X509Certificate2 Load(string rawValue, string? password, string displayName)
    {
        ArgumentNullException.ThrowIfNull(rawValue);

        try
        {
            var certificate = rawValue.Contains("-----BEGIN", StringComparison.Ordinal)
                ? LoadPem(rawValue, password)
                : LoadPkcs12(Convert.FromBase64String(rawValue), password);

            if (!certificate.HasPrivateKey)
            {
                certificate.Dispose();
                throw new FormatException("The certificate has no private key.");
            }

            return certificate;
        }
        catch (Exception ex) when (
            ex is CryptographicException
                or FormatException
                or ArgumentException        // bad base64
                or AsnContentException
                or NotSupportedException)
        {
            // The inner message can quote key-file details; keep only the kind.
            throw new InvalidOperationException(
                $"The client certificate '{displayName}' cannot be loaded ({ex.GetType().Name}).", ex);
        }
    }

    private static X509Certificate2 LoadPkcs12(byte[] data, string? password)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(data, password);
#else
        return new X509Certificate2(data, password);
#endif
    }

    private static X509Certificate2 LoadPem(string bundle, string? password)
    {
        var certificates = new StringBuilder();
        var certificateCount = 0;
        string? keyPem = null;

        var remaining = bundle.AsSpan();
        while (PemEncoding.TryFind(remaining, out var field))
        {
            var content = Convert.FromBase64String(remaining[field.Base64Data].ToString());
            var label = remaining[field.Label].ToString();

            if (label.Equals("CERTIFICATE", StringComparison.Ordinal))
            {
                // WriteString emits no trailing newline; blocks must stay separated so a
                // chain re-encodes into parseable PEM.
                if (certificates.Length > 0)
                {
                    certificates.Append('\n');
                }

                certificates.Append(PemEncoding.WriteString(label, content));
                certificateCount++;
            }
            else if (keyPem is null && label.EndsWith("PRIVATE KEY", StringComparison.Ordinal))
            {
                // Encrypted keys must be PKCS#8 ("ENCRYPTED PRIVATE KEY"); the password
                // decrypts them to a plain PKCS#8 PEM for CreateFromPem, which has no
                // password overload. Legacy encrypted PKCS#1 (Proc-Type headers) is not
                // accepted — it fails the load with a named-reference error.
                keyPem = label.Equals("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)
                    ? DecryptPkcs8(content, password)
                    : PemEncoding.WriteString(label, content);
            }

            remaining = remaining[field.Location.End..];
        }

        if (certificateCount == 0)
        {
            throw new FormatException("The PEM bundle contains no certificate.");
        }

        if (keyPem is null)
        {
            throw new FormatException("The PEM bundle contains no private key.");
        }

        return X509Certificate2.CreateFromPem(certificates.ToString(), keyPem);
    }

    private static string DecryptPkcs8(byte[] encryptedDer, string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new FormatException("The private key is encrypted but no password is configured.");
        }

        // The key algorithm is not in the label; try RSA, then EC. A wrong password
        // surfaces as a CryptographicException from the second attempt, which Load()
        // reports as a load failure naming the reference.
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedDer, out _);
            return PemEncoding.WriteString("PRIVATE KEY", rsa.ExportPkcs8PrivateKey());
        }
        catch (CryptographicException)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportEncryptedPkcs8PrivateKey(password, encryptedDer, out _);
            return PemEncoding.WriteString("PRIVATE KEY", ecdsa.ExportPkcs8PrivateKey());
        }
    }
}
